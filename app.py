from __future__ import annotations

import hashlib
import csv
import io
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dtsx_parser import LINEAGE_COLUMNS, STANDARD_COLUMNS, parse_dtsx_bytes


DEFAULT_VOLUME_PATH = os.getenv("DTSX_VOLUME_PATH", "/Volumes/btris_dbx/ssis_lineage/dtsx_packages")
INCOMING_SUBDIR = os.getenv("DTSX_INCOMING_SUBDIR", "incoming").strip().strip("/")
DEFAULT_INCOMING_FOLDER = os.getenv("DTSX_PACKAGE_FOLDER", f"{DEFAULT_VOLUME_PATH.rstrip('/')}/{INCOMING_SUBDIR}")
JOB_PACKAGE_CSV_PATH = os.getenv("JOB_PACKAGE_CSV_PATH", f"{DEFAULT_VOLUME_PATH.rstrip('/')}/{os.getenv('JOB_PACKAGE_CSV_SUBPATH', 'metadata/listofpackages.csv').strip().strip('/')}")
JOB_HISTORY_CSV_PATH = os.getenv("JOB_HISTORY_CSV_PATH", f"{DEFAULT_VOLUME_PATH.rstrip('/')}/{os.getenv('JOB_HISTORY_CSV_SUBPATH', 'metadata/sqljobshistory_normalized.csv').strip().strip('/')}")
DEFAULT_LLM_ENDPOINT = os.getenv("LLM_ENDPOINT_NAME", os.getenv("DATABRICKS_LLM_ENDPOINT", "databricks-meta-llama-3-3-70b-instruct"))
JOB_PACKAGE_TABLE = os.getenv("JOB_PACKAGE_TABLE", "").strip()
JOB_HISTORY_TABLE = os.getenv("JOB_HISTORY_TABLE", "").strip()
DATABRICKS_WAREHOUSE_ID = os.getenv("DATABRICKS_WAREHOUSE_ID", "").strip()

JOB_COLUMNS = [
    "servername",
    "job_name",
    "job_enabled_state",
    "step_id",
    "step_name",
    "subsystem",
    "job_step_command",
    "package_source_type",
    "package_path",
    "dtsx_package_name",
    "server_folder",
    "step_label",
]


JOB_HISTORY_COLUMNS = [
    "server_name",
    "job_name",
    "step_id",
    "step_name",
    "step_label",
    "run_date",
    "environment",
    "error_category",
    "error_code",
    "sql_state",
    "executed_as",
    "message_excerpt",
    "message",
    "message_hash",
]


class VolumeAccessError(RuntimeError):
    pass


@dataclass(frozen=True)
class PackageResolution:
    package_name: str
    status: str
    resolved_path: str
    expected_path: str
    search_folder: str
    access_mode: str
    message: str


class VolumeFileClient:
    def __init__(self) -> None:
        self.workspace_client = None

    def list_dtsx_files(self, folder_path: str) -> list[dict[str, Any]]:
        entries = self.list_directory(folder_path)
        return sorted(
            [
                item for item in entries
                if item["is_file"] and item["name"].lower().endswith(".dtsx")
            ],
            key=lambda item: item["name"].lower(),
        )

    def list_directory(self, folder_path: str) -> list[dict[str, Any]]:
        folder_path = self.validate_folder_path(folder_path)
        local_folder = Path(folder_path)

        if local_folder.exists() and local_folder.is_dir():
            return sorted(
                [
                    {
                        "name": item.name,
                        "path": item.as_posix(),
                        "size_bytes": item.stat().st_size if item.is_file() else 0,
                        "modified_at": self.format_epoch(item.stat().st_mtime),
                        "is_file": item.is_file(),
                        "is_directory": item.is_dir(),
                        "access_mode": "local_volume_mount",
                    }
                    for item in local_folder.iterdir()
                ],
                key=lambda item: item["name"].lower(),
            )

        workspace = self.workspace()
        try:
            entries = list(workspace.files.list_directory_contents(folder_path))
        except Exception as exc:
            raise VolumeAccessError(self.format_volume_error("list files", folder_path, exc)) from exc

        results = []
        for entry in entries:
            path = str(getattr(entry, "path", "") or getattr(entry, "file_path", "") or "")
            name = Path(path).name if path else str(getattr(entry, "name", ""))
            is_directory = bool(getattr(entry, "is_directory", False))
            size = getattr(entry, "file_size", None)
            modified = getattr(entry, "last_modified", None)

            results.append(
                {
                    "name": name,
                    "path": path or f"{folder_path.rstrip('/')}/{name}",
                    "size_bytes": int(size or 0),
                    "modified_at": self.format_epoch_ms(modified),
                    "is_file": not is_directory,
                    "is_directory": is_directory,
                    "access_mode": "databricks_files_api",
                }
            )

        return sorted(results, key=lambda item: item["name"].lower())

    def read_dtsx_bytes(self, file_path: str) -> bytes:
        return self.read_file_bytes(self.validate_file_path(file_path, ".dtsx"))

    def read_csv_bytes(self, file_path: str) -> bytes:
        return self.read_file_bytes(self.validate_file_path(file_path, ".csv"))

    def read_file_bytes(self, file_path: str) -> bytes:
        local_file = Path(file_path)

        if local_file.exists() and local_file.is_file():
            return local_file.read_bytes()

        workspace = self.workspace()
        try:
            response = workspace.files.download(file_path)
            content = getattr(response, "contents", response)
            if hasattr(content, "read"):
                return content.read()
            if isinstance(content, bytes):
                return content
        except Exception as exc:
            raise VolumeAccessError(self.format_volume_error("read file", file_path, exc)) from exc

        raise VolumeAccessError(f"Databricks Files API returned an unsupported response for {file_path}")

    def format_volume_error(self, action: str, path: str, exc: Exception) -> str:
        message = str(exc)
        permission_terms = ("USE CATALOG", "USE SCHEMA", "READ VOLUME", "PERMISSION_DENIED", "Unauthorized", "not have")
        if any(term.lower() in message.lower() for term in permission_terms):
            return (
                f"Cannot {action} from {path}. The Databricks App identity needs USE CATALOG, USE SCHEMA, "
                "and READ VOLUME permission on the Unity Catalog volume. Add the UC volume as an app resource "
                "with Can read permission, then restart the app."
            )
        not_found_terms = ("not found", "does not exist", "RESOURCE_DOES_NOT_EXIST", "404")
        if any(term.lower() in message.lower() for term in not_found_terms):
            return f"Cannot {action} from {path}. The path was not found."
        return f"Cannot {action} from {path}. {message.split(' Config:')[0]}"

    def workspace(self):
        if self.workspace_client is None:
            try:
                from databricks.sdk import WorkspaceClient
            except Exception as exc:
                raise VolumeAccessError("databricks-sdk is required when /Volumes is not mounted in the app runtime") from exc

            try:
                self.workspace_client = WorkspaceClient()
            except Exception as exc:
                raise VolumeAccessError(f"Cannot initialize Databricks WorkspaceClient: {exc}") from exc

        return self.workspace_client

    def validate_folder_path(self, folder_path: str) -> str:
        value = self.normalize_path(folder_path)
        if not value.startswith("/Volumes/"):
            raise VolumeAccessError("Only Unity Catalog volume paths under /Volumes are allowed")
        if value.lower().endswith((".dtsx", ".csv")):
            raise VolumeAccessError("Provide a folder path, not a file path")
        return value.rstrip("/")

    def validate_file_path(self, file_path: str, extension: str) -> str:
        value = self.normalize_path(file_path)
        if not value.startswith("/Volumes/"):
            raise VolumeAccessError("Only Unity Catalog volume paths under /Volumes are allowed")
        if not value.lower().endswith(extension.lower()):
            raise VolumeAccessError(f"Only {extension} files are allowed")
        return value

    def normalize_path(self, raw_path: str) -> str:
        value = str(raw_path or "").strip().replace("dbfs:", "", 1)
        parts = [part for part in value.split("/") if part not in {"", "."}]
        if ".." in parts:
            raise VolumeAccessError("Parent directory traversal is not allowed")
        return "/" + "/".join(parts)

    def format_epoch(self, value: float) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))

    def format_epoch_ms(self, value: Any) -> str:
        if not value:
            return ""
        try:
            numeric = int(value)
            if numeric > 10_000_000_000:
                numeric = numeric / 1000
            return self.format_epoch(numeric)
        except Exception:
            return str(value)


@st.cache_resource(show_spinner=False)
def volume_client() -> VolumeFileClient:
    return VolumeFileClient()


@st.cache_data(ttl=120, show_spinner=False)
def list_packages(folder_path: str) -> list[dict[str, Any]]:
    return volume_client().list_dtsx_files(folder_path)


@st.cache_data(show_spinner=False)
def parse_package(file_path: str) -> dict[str, Any]:
    content = volume_client().read_dtsx_bytes(file_path)
    return parse_dtsx_bytes(content, source_path=file_path)

@st.cache_data(ttl=120, show_spinner=False)
def load_cached_job_history(csv_path: str, table_name: str, warehouse_id: str) -> pd.DataFrame:
    return load_job_history(csv_path, table_name, warehouse_id)



@st.cache_data(ttl=120, show_spinner=False)
def load_job_catalog(csv_path: str, table_name: str, warehouse_id: str) -> pd.DataFrame:
    if table_name:
        raw = read_catalog_table(table_name, warehouse_id)
    else:
        content = read_catalog_bytes(csv_path)
        raw = read_csv_robust(content, "job package CSV")
    return normalize_job_catalog(raw)


def read_catalog_table(table_name: str, warehouse_id: str) -> pd.DataFrame:
    if not warehouse_id:
        raise ValueError("JOB_PACKAGE_TABLE is set, but DATABRICKS_WAREHOUSE_ID is empty. Add a SQL warehouse app resource or unset JOB_PACKAGE_TABLE to use the CSV path.")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){1,2}", table_name):
        raise ValueError(f"Invalid JOB_PACKAGE_TABLE value: {table_name}")

    workspace = volume_client().workspace()
    statement = f"SELECT servername, job_name, job_enabled_state, step_id, step_name, subsystem, job_step_command, package_source_type, package_path, dtsx_package_name FROM {table_name}"

    response = workspace.statement_execution.execute_statement(
        warehouse_id=warehouse_id,
        statement=statement,
        wait_timeout="30s",
    )

    manifest = getattr(response, "manifest", None)
    result = getattr(response, "result", None)
    columns = []
    data = []

    if manifest is not None:
        schema = getattr(manifest, "schema", None)
        schema_columns = getattr(schema, "columns", []) if schema is not None else []
        columns = [getattr(column, "name", "") for column in schema_columns]

    if result is not None:
        data = getattr(result, "data_array", None) or []

    if not columns:
        columns = ["servername", "job_name", "job_enabled_state", "step_id", "step_name", "subsystem", "job_step_command", "package_source_type", "package_path", "dtsx_package_name"]

    return pd.DataFrame(data, columns=columns)


def read_catalog_bytes(csv_path: str) -> bytes:
    if csv_path.startswith("/Volumes/"):
        return volume_client().read_csv_bytes(csv_path)

    local_path = Path(csv_path)
    if local_path.exists() and local_path.is_file():
        return local_path.read_bytes()

    fallback = Path("listofpackages.csv")
    if fallback.exists() and fallback.is_file():
        return fallback.read_bytes()

    raise FileNotFoundError(
        f"Job package CSV was not found. Upload it to {csv_path}, or set JOB_PACKAGE_CSV_PATH to a readable CSV path."
    )


def read_csv_robust(content: bytes, label: str = "CSV") -> pd.DataFrame:
    errors = []
    read_attempts = [
        {"engine": "c"},
        {"engine": "python"},
        {"engine": "python", "quoting": csv.QUOTE_MINIMAL, "escapechar": "\\", "doublequote": True},
    ]

    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin1"):
        for attempt in read_attempts:
            try:
                return pd.read_csv(io.BytesIO(content), encoding=encoding, **attempt)
            except Exception as exc:
                engine = attempt.get("engine", "c")
                errors.append(f"{encoding}/{engine}: {exc}")

    raise ValueError(
        f"Cannot read {label}. The CSV is probably malformed, usually because long SQL Agent messages contain commas "
        "or quotes but were written without proper CSV quoting. Re-run the ingestion notebook with quote-all CSV output. "
        + " | ".join(errors[:8])
    )


def normalize_job_catalog(raw: pd.DataFrame) -> pd.DataFrame:
    frame = raw.copy()
    frame.columns = [normalize_column_name(column) for column in frame.columns]

    required_without_server = [
        "job_name",
        "job_enabled_state",
        "step_id",
        "step_name",
        "subsystem",
        "job_step_command",
        "package_source_type",
        "package_path",
        "dtsx_package_name",
    ]
    missing = [column for column in required_without_server if column not in frame.columns]
    if missing:
        raise ValueError(f"Job package CSV is missing required column(s): {', '.join(missing)}")

    for column in required_without_server:
        frame[column] = frame[column].map(clean_cell)

    if "servername" not in frame.columns:
        frame["servername"] = frame.apply(derive_server_name, axis=1)
    else:
        frame["servername"] = frame["servername"].map(clean_cell)
        missing_server = frame["servername"].eq("")
        frame.loc[missing_server, "servername"] = frame.loc[missing_server].apply(derive_server_name, axis=1)

    frame["servername"] = frame["servername"].replace("", "UNKNOWN_SERVER")
    frame["server_folder"] = frame["servername"].map(server_folder_name)
    frame["step_id_numeric"] = pd.to_numeric(frame["step_id"], errors="coerce")
    frame["step_id_display"] = frame["step_id"].map(format_step_id)
    frame["step_label"] = frame["step_id_display"] + " - " + frame["step_name"].replace("", "(unnamed step)")
    frame["has_package"] = frame["dtsx_package_name"].map(has_package_name)
    frame["dtsx_package_name"] = frame["dtsx_package_name"].map(clean_package_name)

    return frame[JOB_COLUMNS + ["step_id_numeric", "step_id_display", "has_package"]].sort_values(
        ["servername", "job_name", "step_id_numeric", "step_name", "dtsx_package_name"],
        na_position="last",
    ).reset_index(drop=True)




def load_job_history(csv_path: str, table_name: str, warehouse_id: str) -> pd.DataFrame:
    if table_name:
        raw = read_job_history_table(table_name, warehouse_id)
    else:
        content = read_history_bytes(csv_path)
        raw = read_csv_robust(content, "job history CSV")
    return normalize_job_history(raw)


def read_job_history_table(table_name: str, warehouse_id: str) -> pd.DataFrame:
    if not warehouse_id:
        raise ValueError("JOB_HISTORY_TABLE is set, but DATABRICKS_WAREHOUSE_ID is empty. Add a SQL warehouse app resource or unset JOB_HISTORY_TABLE to use the CSV path.")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){1,2}", table_name):
        raise ValueError(f"Invalid JOB_HISTORY_TABLE value: {table_name}")

    workspace = volume_client().workspace()
    response = workspace.statement_execution.execute_statement(
        warehouse_id=warehouse_id,
        statement=f"SELECT * FROM {table_name}",
        wait_timeout="30s",
    )

    manifest = getattr(response, "manifest", None)
    result = getattr(response, "result", None)
    columns = []
    data = []

    if manifest is not None:
        schema = getattr(manifest, "schema", None)
        schema_columns = getattr(schema, "columns", []) if schema is not None else []
        columns = [getattr(column, "name", "") for column in schema_columns]

    if result is not None:
        data = getattr(result, "data_array", None) or []

    return pd.DataFrame(data, columns=columns)


def read_history_bytes(csv_path: str) -> bytes:
    if csv_path.startswith("/Volumes/"):
        return volume_client().read_csv_bytes(csv_path)

    local_path = Path(csv_path)
    if local_path.exists() and local_path.is_file():
        return local_path.read_bytes()

    for fallback_name in ("sqljobshistory_normalized.csv", "sqljobshistory.csv"):
        fallback = Path(fallback_name)
        if fallback.exists() and fallback.is_file():
            return fallback.read_bytes()

    raise FileNotFoundError(
        f"Job history CSV was not found. Upload it to {csv_path}, or set JOB_HISTORY_CSV_PATH to a readable CSV path."
    )


def normalize_job_history(raw: pd.DataFrame) -> pd.DataFrame:
    frame = raw.copy()
    frame.columns = [normalize_column_name(column) for column in frame.columns]

    rename_map = {
        "servername": "server_name",
        "servername1": "server_name",
        "server": "server_name",
        "server_name": "server_name",
        "jobname": "job_name",
        "jobname1": "job_name",
        "job_name": "job_name",
        "environment": "environment",
    }
    frame = frame.rename(columns={column: rename_map[column] for column in frame.columns if column in rename_map})

    if "environment" not in frame.columns:
        frame["environment"] = ""

    required = ["server_name", "job_name", "step_id", "step_name", "run_date", "message"]
    missing = [column for column in required if column not in frame.columns]
    if missing:
        raise ValueError(f"Job history CSV is missing required column(s): {', '.join(missing)}")

    for column in ["server_name", "job_name", "step_id", "step_name", "run_date", "environment", "message"]:
        frame[column] = frame[column].map(clean_cell)

    frame = frame[frame["message"].str.strip().ne("")].copy()
    frame["server_name"] = frame["server_name"].replace("", "UNKNOWN_SERVER")
    frame["job_name"] = frame["job_name"].replace("", "UNKNOWN_JOB")
    frame["step_id_numeric"] = pd.to_numeric(frame["step_id"], errors="coerce")
    frame["step_id_display"] = frame["step_id"].map(format_step_id)
    frame["step_label"] = frame["step_id_display"] + " - " + frame["step_name"].replace("", "(unnamed step)")
    frame["run_date"] = frame["run_date"].map(normalize_run_date_value)
    frame["error_category"] = frame["message"].map(classify_error_message)
    frame["error_code"] = frame["message"].map(lambda value: extract_first_match(value, r"(?i)\b(?:Code:\s*)?(0x[0-9a-f]{8})\b|\(Error\s+([0-9]+)\)"))
    frame["sql_state"] = frame["message"].map(lambda value: extract_first_match(value, r"(?i)SQLSTATE\s+([A-Z0-9]+)"))
    frame["executed_as"] = frame["message"].map(lambda value: extract_first_match(value, r"(?i)Executed as user:\s*([^\.]+)\."))
    frame["message_excerpt"] = frame["message"].map(lambda value: shorten_text(value, 420))
    frame["message_hash"] = frame["message"].map(lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest())
    frame["server_key"] = frame["server_name"].map(server_folder_name)
    frame["job_key"] = frame["job_name"].map(normalized_match_key)
    frame["step_key"] = frame["step_label"].map(normalized_match_key)
    frame["step_name_key"] = frame["step_name"].map(normalized_match_key)

    return frame[JOB_HISTORY_COLUMNS + ["server_key", "job_key", "step_key", "step_name_key", "step_id_numeric", "step_id_display"]].sort_values(
        ["server_name", "job_name", "step_id_numeric", "run_date"],
        na_position="last",
    ).reset_index(drop=True)


def normalize_run_date_value(value: Any) -> str:
    text = clean_cell(value)
    if not text:
        return ""

    try:
        numeric = float(text)
        if numeric > 10000101:
            text = str(int(round(numeric)))
    except Exception:
        pass

    digits = re.sub(r"\D", "", text)
    if len(digits) >= 8:
        candidate = digits[:8]
        try:
            parsed = pd.to_datetime(candidate, format="%Y%m%d", errors="raise")
            return parsed.strftime("%Y-%m-%d")
        except Exception:
            return candidate

    parsed = pd.to_datetime(text, errors="coerce")
    if pd.notna(parsed):
        return parsed.strftime("%Y-%m-%d")

    return text


def classify_error_message(message: Any) -> str:
    text = clean_cell(message).lower()

    if not text:
        return "Unknown"
    if "column name or number of supplied values" in text or "does not match table definition" in text:
        return "Schema mismatch"
    if "failed to decrypt protected xml node" in text or "not authorized to access this information" in text:
        return "SSIS protection/decryption"
    if "could not connect to server" in text or "remote logins" in text:
        return "Remote server/login configuration"
    if "could not load package" in text or "specified package could not be loaded" in text:
        return "Package load failure"
    if "ole db error" in text or "dts_e_oledberror" in text or "dynamicconnection" in text:
        return "OLE DB connection failure"
    if "timeout expired" in text or "timeout period elapsed" in text:
        return "Execution timeout"
    if "system cannot find the file specified" in text or "not found" in text or "does not exist" in text:
        return "Missing file or executable"
    if "package execution failed" in text:
        return "Package execution failed"
    if "execute sql task" in text or "executing the query" in text:
        return "Execute SQL task failure"
    if "process exit code" in text:
        return "External process failure"

    return "Other SQL Agent failure"


def extract_first_match(value: Any, pattern: str) -> str:
    text = clean_cell(value)
    match = re.search(pattern, text)
    if not match:
        return ""
    for group in match.groups():
        if group:
            return group
    return match.group(0)


def normalized_match_key(value: Any) -> str:
    return re.sub(r"\s+", " ", clean_cell(value).lower()).strip()


def shorten_text(value: Any, max_length: int = 240) -> str:
    text = clean_cell(value)
    if len(text) <= max_length:
        return text
    return text[: max_length - 3].rstrip() + "..."


def normalize_column_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", str(value).strip().lower()).strip("_")


def clean_cell(value: Any) -> str:
    if pd.isna(value):
        return ""
    text = str(value).replace("\xa0", " ").strip()
    return "" if text.lower() in {"nan", "none", "null"} else text


def clean_package_name(value: Any) -> str:
    text = clean_cell(value).replace("\\", "/")
    if not text:
        return ""
    return Path(text).name


def has_package_name(value: Any) -> bool:
    return bool(clean_package_name(value))


def format_step_id(value: Any) -> str:
    text = clean_cell(value)
    try:
        numeric = float(text)
        if numeric.is_integer():
            return str(int(numeric))
    except Exception:
        return text
    return text


def derive_server_name(row: pd.Series) -> str:
    combined = " ".join(
        [
            clean_cell(row.get("servername", "")),
            clean_cell(row.get("package_path", "")),
            clean_cell(row.get("job_step_command", "")),
        ]
    )

    unc_match = re.search(r"\\\\([^\\/\s\"']+)[\\/]", combined)
    if unc_match:
        return unc_match.group(1)

    server_match = re.search(r"/SERVER\s+\"?([^\"\s]+)", combined, flags=re.IGNORECASE)
    if server_match:
        return server_match.group(1)

    server_match = re.search(r"/Server\s+\"?([^\"\s]+)", combined)
    if server_match:
        return server_match.group(1)

    return "UNKNOWN_SERVER"


def server_folder_name(server_name: str) -> str:
    value = clean_cell(server_name)
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return value or "UNKNOWN_SERVER"


def package_lookup_key(package_name: str) -> str:
    return clean_package_name(package_name).lower()


def unique_sorted(values: pd.Series) -> list[str]:
    return sorted([value for value in values.dropna().astype(str).unique().tolist() if value.strip()], key=str.lower)


def build_package_resolution(package_name: str, server_name: str, incoming_folder: str) -> PackageResolution:
    package_name = clean_package_name(package_name)
    server_folder = server_folder_name(server_name)
    expected_folder = f"{incoming_folder.rstrip('/')}/{server_folder}"
    expected_path = f"{expected_folder}/{package_name}" if package_name else expected_folder

    if not package_name:
        return PackageResolution("", "no_package", "", expected_path, expected_folder, "", "This SQL Agent step does not reference a DTSX package.")

    candidate_folders = []
    candidate_folders.append(expected_folder)

    exact_server_folder = clean_cell(server_name).replace("\\", "_").replace("/", "_").strip()
    if exact_server_folder and exact_server_folder != server_folder:
        candidate_folders.append(f"{incoming_folder.rstrip('/')}/{exact_server_folder}")

    candidate_folders.append(incoming_folder.rstrip("/"))

    seen = set()
    deduped_folders = []
    for folder in candidate_folders:
        if folder not in seen:
            deduped_folders.append(folder)
            seen.add(folder)

    errors = []
    package_key = package_lookup_key(package_name)

    for folder in deduped_folders:
        try:
            files = list_packages(folder)
        except Exception as exc:
            errors.append(f"{folder}: {exc}")
            continue

        for file_info in files:
            if package_lookup_key(file_info["name"]) == package_key:
                status = "available" if folder == expected_folder else "available_root_fallback"
                return PackageResolution(
                    package_name,
                    status,
                    file_info["path"],
                    expected_path,
                    folder,
                    file_info.get("access_mode", ""),
                    "Package found in the server folder." if status == "available" else "Package found in the root incoming folder fallback.",
                )

    message = "Package was not found in the server folder or root incoming fallback."
    if errors:
        message = f"{message} Listing errors: {' | '.join(errors[:3])}"

    return PackageResolution(package_name, "missing", "", expected_path, expected_folder, "", message)


def package_resolution_frame(packages: list[str], server_name: str, incoming_folder: str) -> pd.DataFrame:
    resolutions = [build_package_resolution(package, server_name, incoming_folder) for package in packages]
    return pd.DataFrame(
        [
            {
                "package_name": item.package_name,
                "status": item.status,
                "resolved_path": item.resolved_path,
                "expected_path": item.expected_path,
                "search_folder": item.search_folder,
                "access_mode": item.access_mode,
                "message": item.message,
            }
            for item in resolutions
        ]
    )



def adaptive_dataframe_height(
    row_count: int,
    *,
    min_rows: int = 1,
    max_rows: int = 12,
    row_height: int = 35,
    header_height: int = 38,
    frame_padding: int = 8,
) -> int:
    visible_rows = max(min_rows, min(max_rows, int(row_count or 0)))
    return header_height + visible_rows * row_height + frame_padding


def page_setup() -> None:
    st.set_page_config(
        page_title="SQL Agent SSIS DTSX Lineage Intelligence",
        page_icon="🧭",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(
        """
        <style>
        .block-container {padding-top: 1.2rem; padding-bottom: 2rem;}
        div[data-testid="stMetric"] {background: linear-gradient(135deg, rgba(49,91,255,.08), rgba(126,87,194,.08)); border: 1px solid rgba(49,91,255,.15); padding: 1rem; border-radius: 1rem;}
        .lineage-hero {padding: 1.15rem 1.25rem; border: 1px solid rgba(255,255,255,.08); border-radius: 1.1rem; background: linear-gradient(135deg, rgba(30,64,175,.16), rgba(124,58,237,.12));}
        .lineage-muted {color: #7f8c9a; font-size: .9rem;}
        .status-card {padding: .8rem 1rem; border-radius: .9rem; border: 1px solid rgba(125,125,125,.18); background: rgba(125,125,125,.06);}
        .good-card {padding: .8rem 1rem; border-radius: .9rem; border: 1px solid rgba(22,163,74,.25); background: rgba(22,163,74,.08);}
        .warn-card {padding: .8rem 1rem; border-radius: .9rem; border: 1px solid rgba(217,119,6,.25); background: rgba(217,119,6,.08);}
        </style>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    page_setup()
    st.markdown(
        """
        <div class="lineage-hero">
            <h1 style="margin:0;">SQL Agent SSIS DTSX Lineage Intelligence</h1>
            <div class="lineage-muted">Select SQL Server, job, step, and package from the job catalog, then resolve the DTSX from Unity Catalog Volumes.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    incoming_folder = volume_client().validate_folder_path(DEFAULT_INCOMING_FOLDER)

    with st.sidebar:
        st.subheader("Catalog source")
        st.caption("Job-step package metadata source")
        if JOB_PACKAGE_TABLE:
            st.code(JOB_PACKAGE_TABLE, language="text")
        else:
            st.code(JOB_PACKAGE_CSV_PATH, language="text")

        st.caption("Job error history source")
        if JOB_HISTORY_TABLE:
            st.code(JOB_HISTORY_TABLE, language="text")
        else:
            st.code(JOB_HISTORY_CSV_PATH, language="text")

        st.caption("DTSX incoming root")
        st.code(incoming_folder, language="text")
        refresh_clicked = st.button("Refresh catalog and package cache", use_container_width=True)

        if refresh_clicked:
            st.cache_data.clear()

        st.divider()
        st.subheader("LLM summary")
        llm_endpoint = st.text_input("Serving endpoint", value=DEFAULT_LLM_ENDPOINT)
        auto_summary = st.toggle("Generate summary", value=True)
        st.caption("The app is read-only. It reads job catalogs, job history, and DTSX packages from the volume, then parses package metadata in memory.")

    try:
        job_catalog = load_job_catalog(JOB_PACKAGE_CSV_PATH, JOB_PACKAGE_TABLE, DATABRICKS_WAREHOUSE_ID)
    except Exception as exc:
        st.error(str(exc))
        st.stop()

    history_error = ""
    job_history = pd.DataFrame(columns=JOB_HISTORY_COLUMNS)
    try:
        job_history = load_cached_job_history(JOB_HISTORY_CSV_PATH, JOB_HISTORY_TABLE, DATABRICKS_WAREHOUSE_ID)
    except Exception as exc:
        history_error = str(exc)

    overview_tab, error_tab, metadata_tab, lineage_tab, neo4j_tab, architecture_tab, catalog_tab, json_tab = st.tabs(
    [
        "Overview",
        "Job Error Analysis",
        "Metadata Table",
        "Lineage Sankey",
        "Neo4j Graph",
        "Architecture Inventory",
        "Job Catalog",
        "Parsed JSON",]
    )

    with overview_tab:
        selection = render_job_package_selector(job_catalog, incoming_folder)

    selected_resolution = selection.get("selected_resolution")
    parsed: dict[str, Any] | None = None
    metadata_df = pd.DataFrame(columns=STANDARD_COLUMNS)
    lineage_df = pd.DataFrame(columns=LINEAGE_COLUMNS)
    profile: dict[str, Any] = {}

    if selected_resolution and selected_resolution.status.startswith("available"):
        with st.spinner("Parsing selected DTSX package architecture..."):
            parsed = parse_package(selected_resolution.resolved_path)
        metadata_df = pd.DataFrame(parsed.get("metadata_rows", []), columns=STANDARD_COLUMNS)
        lineage_df = pd.DataFrame(parsed.get("lineage_edges", []), columns=LINEAGE_COLUMNS)
        profile = package_profile(parsed, metadata_df, lineage_df)

    with overview_tab:
        render_selected_package_overview(selection, parsed, profile, llm_endpoint, auto_summary)

    with error_tab:
        render_job_error_analysis(job_history, history_error, selection, llm_endpoint, auto_summary)

    with metadata_tab:
        if parsed:
            render_metadata_table(metadata_df)
        else:
            render_no_package_state(selection)

    with lineage_tab:
        if parsed:
            render_lineage(lineage_df)
        else:
            render_no_package_state(selection)

    with neo4j_tab:
        if parsed:
            render_neo4j_graph(lineage_df)
        else:
            render_no_package_state(selection)
    with architecture_tab:
        if parsed:
            render_architecture(parsed)
        else:
            render_no_package_state(selection)

    with catalog_tab:
        render_catalog(job_catalog, selection, incoming_folder)

    with json_tab:
        if parsed:
            render_json(parsed)
        else:
            render_no_package_state(selection)


def render_job_package_selector(job_catalog: pd.DataFrame, incoming_folder: str) -> dict[str, Any]:
    st.subheader("SQL Agent job package selector")

    metric_columns = st.columns(5)
    metric_columns[0].metric("Servers", job_catalog["servername"].nunique())
    metric_columns[1].metric("Jobs", job_catalog["job_name"].nunique())
    metric_columns[2].metric("Job steps", len(job_catalog))
    metric_columns[3].metric("Distinct packages", job_catalog.loc[job_catalog["has_package"], "dtsx_package_name"].nunique())
    metric_columns[4].metric("Null package steps", int((~job_catalog["has_package"]).sum()))

    server_options = unique_sorted(job_catalog["servername"])
    if not server_options:
        st.warning("No server names were found in the job catalog.")
        return {}

    selector_row = st.columns([1.2, 1.6, 1.4])
    selected_server = selector_row[0].selectbox("Server", server_options)

    server_df = job_catalog[job_catalog["servername"] == selected_server].copy()
    enabled_states = ["All states"] + unique_sorted(server_df["job_enabled_state"])
    selected_state = selector_row[1].selectbox("Job enabled state", enabled_states)

    if selected_state != "All states":
        server_df = server_df[server_df["job_enabled_state"] == selected_state]

    job_options = unique_sorted(server_df["job_name"])
    if not job_options:
        st.warning("No jobs match the selected server and state.")
        return {"selected_server": selected_server}

    selected_job = selector_row[2].selectbox("Job", job_options)
    job_df = server_df[server_df["job_name"] == selected_job].copy()

    job_table = (
        server_df.groupby(["job_name", "job_enabled_state"], dropna=False)
        .agg(
            step_count=("step_id", "count"),
            package_step_count=("has_package", "sum"),
            distinct_package_count=("dtsx_package_name", lambda values: values[values.astype(str).str.strip().ne("")].nunique()),
        )
        .reset_index()
        .sort_values(["job_enabled_state", "job_name"])
    )

    st.markdown("#### Jobs on selected server")
    st.dataframe(job_table, use_container_width=True, hide_index=True, height=260)

    step_options = (
        job_df[["step_id_numeric", "step_label"]]
        .drop_duplicates()
        .sort_values(["step_id_numeric", "step_label"], na_position="last")["step_label"]
        .tolist()
    )

    step_package_row = st.columns([1.6, 1.4])
    selected_step = step_package_row[0].selectbox("Job step", step_options)
    step_df = job_df[job_df["step_label"] == selected_step].copy()

    packages = unique_sorted(step_df.loc[step_df["has_package"], "dtsx_package_name"])
    resolution_df = package_resolution_frame(packages, selected_server, incoming_folder) if packages else pd.DataFrame(
        [
            {
                "package_name": "",
                "status": "no_package",
                "resolved_path": "",
                "expected_path": f"{incoming_folder.rstrip('/')}/{server_folder_name(selected_server)}",
                "search_folder": f"{incoming_folder.rstrip('/')}/{server_folder_name(selected_server)}",
                "access_mode": "",
                "message": "This SQL Agent step does not reference a DTSX package.",
            }
        ]
    )

    package_options = resolution_df["package_name"].tolist()
    package_options = [package for package in package_options if package]

    selected_package = ""
    selected_resolution = None

    if package_options:
        selected_package = step_package_row[1].selectbox("Package referenced by step", package_options)
        selected_row = resolution_df[resolution_df["package_name"] == selected_package].iloc[0].to_dict()
        selected_resolution = PackageResolution(**selected_row)
    else:
        step_package_row[1].text_input("Package referenced by step", value="No DTSX package referenced", disabled=True)

    st.markdown("#### Packages for selected step")
    st.dataframe(
        resolution_df,
        use_container_width=True,
        hide_index=True,
        height=adaptive_dataframe_height(len(resolution_df), max_rows=10),
    )

    expected_folder = f"{incoming_folder.rstrip('/')}/{server_folder_name(selected_server)}"
    st.markdown(
        f"""
        <div class="status-card">
            <b>Expected customer upload folder for this server</b><br/>
            <span class="lineage-muted">{expected_folder}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if selected_resolution:
        render_resolution_card(selected_resolution)

    return {
        "selected_server": selected_server,
        "selected_job": selected_job,
        "selected_step": selected_step,
        "selected_package": selected_package,
        "selected_resolution": selected_resolution,
        "server_df": server_df,
        "job_df": job_df,
        "step_df": step_df,
        "resolution_df": resolution_df,
    }


def render_resolution_card(resolution: PackageResolution) -> None:
    if resolution.status.startswith("available"):
        st.markdown(
            f"""
            <div class="good-card">
                <b>Package resolved</b><br/>
                <span class="lineage-muted">{resolution.resolved_path}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    st.markdown(
        f"""
        <div class="warn-card">
            <b>Package not available in the volume</b><br/>
            <span class="lineage-muted">Expected path: {resolution.expected_path}</span><br/>
            <span class="lineage-muted">{resolution.message}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_selected_package_overview(
    selection: dict[str, Any],
    parsed: dict[str, Any] | None,
    profile: dict[str, Any],
    llm_endpoint: str,
    auto_summary: bool,
) -> None:
    resolution = selection.get("selected_resolution")
    if not resolution or not parsed:
        return

    package = parsed.get("package", {})
    st.divider()
    st.subheader(package.get("name", "Package"))

    cols = st.columns(6)
    cols[0].metric("Connections", profile["connections"])
    cols[1].metric("Executables", profile["executables"])
    cols[2].metric("SQL Tasks", profile["sql_tasks"])
    cols[3].metric("Data Flows", profile["data_flows"])
    cols[4].metric("Metadata Rows", profile["metadata_rows"])
    cols[5].metric("Lineage Edges", profile["lineage_edges"])

    if auto_summary:
        with st.spinner("Generating package summary..."):
            summary = generate_or_fallback_summary(parsed, llm_endpoint)
        st.info(summary)

    detail_left, detail_right = st.columns([1, 1])
    with detail_left:
        st.markdown("#### SQL Agent context")
        context = pd.DataFrame(
            [
                ("Server", selection.get("selected_server", "")),
                ("Job", selection.get("selected_job", "")),
                ("Step", selection.get("selected_step", "")),
                ("Referenced package", selection.get("selected_package", "")),
                ("Resolved path", resolution.resolved_path),
                ("Resolution status", resolution.status),
            ],
            columns=["property", "value"],
        )
        st.dataframe(context, use_container_width=True, hide_index=True)

    with detail_right:
        st.markdown("#### Package identity")
        identity = pd.DataFrame(
            [
                ("Package name", package.get("name", "")),
                ("Creation name", package.get("creation_name", "")),
                ("Executable type", package.get("executable_type", "")),
                ("Creator", package.get("creator_name", "")),
                ("Product version", package.get("last_modified_product_version", "")),
                ("SHA-256", parsed.get("sha256", "")),
            ],
            columns=["property", "value"],
        )
        st.dataframe(identity, use_container_width=True, hide_index=True)


def render_no_package_state(selection: dict[str, Any]) -> None:
    resolution = selection.get("selected_resolution")
    if resolution is None:
        st.info("Select a server, job, step, and package in the Overview tab.")
        return
    if resolution.status == "no_package":
        st.warning("The selected step does not reference a DTSX package.")
        return
    st.warning(f"The selected package is not available for parsing. Expected path: {resolution.expected_path}")


def render_catalog(job_catalog: pd.DataFrame, selection: dict[str, Any], incoming_folder: str) -> None:
    st.subheader("Normalized job package catalog")

    server = selection.get("selected_server", "")
    filtered = job_catalog.copy()

    filter_cols = st.columns([1, 1, 2])
    server_options = ["All servers"] + unique_sorted(job_catalog["servername"])
    selected_server = filter_cols[0].selectbox("Catalog server filter", server_options, index=server_options.index(server) if server in server_options else 0)

    state_options = ["All states"] + unique_sorted(job_catalog["job_enabled_state"])
    selected_state = filter_cols[1].selectbox("Catalog state filter", state_options)

    search = filter_cols[2].text_input("Search catalog", placeholder="job, step, package, command, path")

    if selected_server != "All servers":
        filtered = filtered[filtered["servername"] == selected_server]
    if selected_state != "All states":
        filtered = filtered[filtered["job_enabled_state"] == selected_state]
    if search.strip():
        needle = search.strip().lower()
        searchable = filtered[
            ["servername", "job_name", "step_label", "subsystem", "job_step_command", "package_path", "dtsx_package_name"]
        ].fillna("").agg(" ".join, axis=1).str.lower()
        filtered = filtered[searchable.str.contains(needle, regex=False)]

    st.caption(f"{len(filtered):,} rows shown from {len(job_catalog):,} catalog rows.")
    st.dataframe(filtered[JOB_COLUMNS], use_container_width=True, hide_index=True, height=620)

    st.markdown("#### Folder convention")
    st.code(f"{incoming_folder.rstrip('/')}/<server_folder>/<dtsx_package_name>", language="text")


def render_job_error_analysis(
    job_history: pd.DataFrame,
    history_error: str,
    selection: dict[str, Any],
    endpoint_name: str,
    auto_summary: bool,
) -> None:
    st.subheader("SQL Agent job error analysis")

    if history_error:
        st.warning(history_error)
        st.caption("Run the job history ingestion notebook first, then restart or refresh the app cache.")
        return

    if job_history.empty:
        st.warning("No job history error rows were loaded.")
        return

    selected_server = clean_cell(selection.get("selected_server", ""))
    selected_job = clean_cell(selection.get("selected_job", ""))
    selected_step = clean_cell(selection.get("selected_step", ""))

    metrics = st.columns(5)
    metrics[0].metric("History rows", len(job_history))
    metrics[1].metric("Servers", job_history["server_name"].nunique())
    metrics[2].metric("Jobs with errors", job_history["job_name"].nunique())
    metrics[3].metric("Error categories", job_history["error_category"].nunique())
    metrics[4].metric("Latest run date", max(unique_sorted(job_history["run_date"])) if unique_sorted(job_history["run_date"]) else "n/a")

    default_scope = "Current Overview selection" if selected_server and selected_job else "Browse error history"
    scope_options = ["Current Overview selection", "Browse error history"]
    scope = st.radio("Error history scope", scope_options, horizontal=True, index=scope_options.index(default_scope))

    if scope == "Current Overview selection":
        filtered = filter_history_for_selection(job_history, selection)
        st.caption(f"Current selection: {selected_server or '(no server)'} → {selected_job or '(no job)'} → {selected_step or '(no step)'}")
    else:
        filtered = filter_history_manually(job_history)

    if filtered.empty:
        st.info("No error history rows match the selected scope.")
        st.dataframe(
            job_history[["run_date", "environment", "server_name", "job_name", "step_label", "error_category", "message_excerpt"]].head(50),
            use_container_width=True,
            hide_index=True,
            height=adaptive_dataframe_height(min(len(job_history), 10), max_rows=10),
        )
        return

    category_summary = (
        filtered.groupby("error_category", dropna=False)
        .size()
        .reset_index(name="error_count")
        .sort_values("error_count", ascending=False)
    )

    st.markdown("#### Error category summary")
    st.dataframe(
        category_summary,
        use_container_width=True,
        hide_index=True,
        height=adaptive_dataframe_height(len(category_summary), max_rows=8),
    )

    st.markdown("#### Error rows")
    display_columns = [
        "run_date",
        "environment",
        "server_name",
        "job_name",
        "step_label",
        "error_category",
        "error_code",
        "sql_state",
        "executed_as",
        "message_excerpt",
        "message",
    ]
    st.dataframe(
        filtered[display_columns],
        use_container_width=True,
        hide_index=True,
        height=adaptive_dataframe_height(len(filtered), max_rows=8, row_height=42),
    )

    if auto_summary:
        with st.spinner("Generating error overview and remediation steps..."):
            analysis = generate_or_fallback_job_error_analysis(filtered, endpoint_name)
        st.markdown("#### LLM error overview and fix plan")
        st.markdown(analysis)
    else:
        st.info("Enable 'Generate summary' in the sidebar to create the LLM error overview and fix steps.")


def filter_history_for_selection(job_history: pd.DataFrame, selection: dict[str, Any]) -> pd.DataFrame:
    server = clean_cell(selection.get("selected_server", ""))
    job = clean_cell(selection.get("selected_job", ""))
    step_df = selection.get("step_df")
    step_id_display = ""
    step_name = ""

    if isinstance(step_df, pd.DataFrame) and not step_df.empty:
        step_id_display = clean_cell(step_df["step_id_display"].iloc[0]) if "step_id_display" in step_df.columns else ""
        step_name = clean_cell(step_df["step_name"].iloc[0]) if "step_name" in step_df.columns else ""

    filtered = job_history.copy()

    if server:
        filtered = filtered[filtered["server_key"] == server_folder_name(server)]

    if job:
        filtered = filtered[filtered["job_key"] == normalized_match_key(job)]

    if step_id_display:
        filtered = filtered[filtered["step_id_display"] == step_id_display]

    if step_name and not filtered.empty:
        step_name_key = normalized_match_key(step_name)
        exact_step = filtered[filtered["step_name_key"] == step_name_key]
        if not exact_step.empty:
            filtered = exact_step

    return filtered.reset_index(drop=True)


def filter_history_manually(job_history: pd.DataFrame) -> pd.DataFrame:
    filter_row = st.columns([1, 1.6, 1.4])

    server_options = unique_sorted(job_history["server_name"])
    selected_server = filter_row[0].selectbox("History server", server_options)

    server_df = job_history[job_history["server_name"] == selected_server].copy()
    job_options = unique_sorted(server_df["job_name"])
    selected_job = filter_row[1].selectbox("History job", job_options)

    job_df = server_df[server_df["job_name"] == selected_job].copy()
    step_options = (
        job_df[["step_id_numeric", "step_label"]]
        .drop_duplicates()
        .sort_values(["step_id_numeric", "step_label"], na_position="last")["step_label"]
        .tolist()
    )
    selected_step = filter_row[2].selectbox("History step", step_options)

    return job_df[job_df["step_label"] == selected_step].copy().reset_index(drop=True)


def render_metadata_table(metadata_df: pd.DataFrame) -> None:
    st.subheader("Standard metadata table")

    col_a, col_b, col_c = st.columns([1, 1, 2])
    asset_types = sorted(metadata_df["asset_type"].dropna().unique().tolist())
    object_types = sorted(metadata_df["object_type"].dropna().unique().tolist())

    selected_assets = col_a.multiselect("Asset type", asset_types, default=asset_types)
    selected_objects = col_b.multiselect("Object type", object_types, default=[])
    search_text = col_c.text_input("Search metadata", placeholder="task, table, column, component, SQL text")

    filtered = metadata_df.copy()
    if selected_assets:
        filtered = filtered[filtered["asset_type"].isin(selected_assets)]
    if selected_objects:
        filtered = filtered[filtered["object_type"].isin(selected_objects)]
    if search_text.strip():
        needle = search_text.strip().lower()
        searchable = filtered[
            [
                "object_name",
                "task_name",
                "component_name",
                "connection_name",
                "source_object",
                "target_object",
                "column_name",
                "expression",
                "sql_excerpt",
            ]
        ].fillna("").agg(" ".join, axis=1).str.lower()
        filtered = filtered[searchable.str.contains(needle, regex=False)]

    st.caption(f"{len(filtered):,} rows shown from {len(metadata_df):,} parsed rows")
    st.dataframe(filtered, use_container_width=True, hide_index=True, height=620)


def render_lineage(lineage_df: pd.DataFrame) -> None:
    st.subheader("Sankey lineage visualization")

    if lineage_df.empty:
        st.warning("No lineage edges were detected.")
        return

    relationship_types = sorted(lineage_df["relationship_type"].dropna().unique().tolist())
    default_types = [item for item in relationship_types if item in {"sql_object_lineage", "data_flow_path"}]
    if not default_types:
        default_types = relationship_types[:3]

    filter_row = st.columns([1.25, .7, 1.05, .7])
    selected_types = filter_row[0].multiselect("Relationship type", relationship_types, default=default_types)
    edge_limit = filter_row[1].slider("Max edges", min_value=20, max_value=500, value=160, step=20)
    object_search = filter_row[2].text_input("Filter graph", placeholder="table, task, column")
    font_size = filter_row[3].slider("Font size", min_value=12, max_value=24, value=17, step=1)

    graph_df = lineage_df[lineage_df["relationship_type"].isin(selected_types)].copy()

    if object_search.strip():
        needle = object_search.strip().lower()
        searchable_columns = ["source", "target", "task_name", "component_name", "source_object", "target_object"]
        searchable = graph_df[searchable_columns].fillna("").agg(" ".join, axis=1).str.lower()
        graph_df = graph_df[searchable.str.contains(needle, regex=False)]

    source_options = ["All sources"] + sorted(
        source for source in graph_df["source"].dropna().astype(str).unique().tolist() if source.strip()
    )

    source_target_row = st.columns([1.3, 1.3, .7])
    selected_source = source_target_row[0].selectbox("Source", source_options)

    source_filtered_df = graph_df
    if selected_source != "All sources":
        source_filtered_df = graph_df[graph_df["source"].astype(str) == selected_source]

    target_options = ["All targets"] + sorted(
        target for target in source_filtered_df["target"].dropna().astype(str).unique().tolist() if target.strip()
    )
    selected_target = source_target_row[1].selectbox("Target", target_options)
    label_max_length = source_target_row[2].slider("Label width", min_value=24, max_value=90, value=56, step=4)

    graph_df = source_filtered_df
    if selected_target != "All targets":
        graph_df = graph_df[graph_df["target"].astype(str) == selected_target]

    total_matching_edges = len(graph_df)
    graph_df = graph_df.head(edge_limit)

    if graph_df.empty:
        st.warning("No lineage edges match the selected filters.")
        return

    st.caption(
        f"Showing {len(graph_df):,} of {total_matching_edges:,} matching lineage edges "
        f"across {graph_df['source'].nunique():,} source node(s) and {graph_df['target'].nunique():,} target node(s). "
        "Use the font-size and label-width controls to improve readability; hover over nodes or links to see full names."
    )

    sankey = build_sankey(graph_df, font_size=font_size, label_max_length=label_max_length)
    st.plotly_chart(sankey, use_container_width=True)
    st.dataframe(graph_df, use_container_width=True, hide_index=True, height=420)

def render_neo4j_graph(lineage_df: pd.DataFrame) -> None:
    st.subheader("Neo4j-style lineage graph")

    widget_prefix = "neo4j_lineage_graph"

    try:
        from streamlit_agraph import agraph, Node, Edge, Config
    except Exception as exc:
        st.error(
            "The Neo4j-style graph dependency is not installed. "
            "Add `streamlit-agraph==0.0.45` to requirements.txt, redeploy the Databricks App, and reopen it."
        )
        st.exception(exc)
        return

    if lineage_df.empty:
        st.warning("No lineage edges were detected.")
        return

    required_columns = {"source", "target", "relationship_type"}
    missing_columns = sorted(required_columns - set(lineage_df.columns))
    if missing_columns:
        st.error(f"Lineage dataframe is missing required column(s): {', '.join(missing_columns)}")
        return

    relationship_types = sorted(
        lineage_df["relationship_type"].fillna("").astype(str).str.strip().replace("", pd.NA).dropna().unique().tolist()
    )

    object_level_types = [
        item for item in relationship_types
        if item in {"sql_object_lineage", "data_flow_path"}
    ]
    control_flow_types = [
        item for item in relationship_types
        if item in {"precedence_constraint"}
    ]
    column_level_types = [
        item for item in relationship_types
        if item in {"column_mapping"}
    ]

    graph_mode = st.radio(
        "Graph level",
        ["Object-level lineage", "Control-flow only", "Column-level mappings", "Full graph"],
        horizontal=True,
        key=f"{widget_prefix}_graph_level",
    )

    graph_mode_key = (
        graph_mode.lower()
        .replace(" ", "_")
        .replace("-", "_")
    )

    if graph_mode == "Object-level lineage":
        default_types = object_level_types or relationship_types[:3]
        default_limit = 250
    elif graph_mode == "Control-flow only":
        default_types = control_flow_types or relationship_types[:1]
        default_limit = 300
    elif graph_mode == "Column-level mappings":
        default_types = column_level_types or relationship_types[:1]
        default_limit = 500
    else:
        default_types = relationship_types
        default_limit = 500

    # filter_row = st.columns([1.4, 0.7, 1.1, 0.8])

    # selected_types = filter_row[0].multiselect(
    #     "Relationship type",
    #     relationship_types,
    #     default=default_types,
    #     key=f"{widget_prefix}_{graph_mode_key}_relationship_types",
    # )

    # edge_limit = filter_row[1].slider(
    #     "Max edges",
    #     min_value=25,
    #     max_value=1000,
    #     value=min(default_limit, 1000),
    #     step=25,
    #     key=f"{widget_prefix}_{graph_mode_key}_edge_limit",
    # )

    # search_text = filter_row[2].text_input(
    #     "Search graph",
    #     placeholder="table, task, component, column",
    #     key=f"{widget_prefix}_{graph_mode_key}_search",
    # )

    # layout_mode = filter_row[3].selectbox(
    #     "Layout",
    #     ["Force-directed", "Hierarchical"],
    #     key=f"{widget_prefix}_{graph_mode_key}_layout",
    # )

    filter_row = st.columns([1.4, 0.7, 1.1, 0.8])

    selected_types = filter_row[0].multiselect(
        "Relationship type",
        relationship_types,
        default=default_types,
        key=f"{widget_prefix}_{graph_mode_key}_relationship_types",
    )

    edge_limit = filter_row[1].slider(
        "Max edges",
        min_value=25,
        max_value=1000,
        value=min(default_limit, 1000),
        step=25,
        key=f"{widget_prefix}_{graph_mode_key}_edge_limit",
    )

    search_text = filter_row[2].text_input(
        "Search all graph fields",
        placeholder="table, task, component, column",
        key=f"{widget_prefix}_{graph_mode_key}_search",
    )

    layout_mode = filter_row[3].selectbox(
        "Layout",
        ["Force-directed", "Hierarchical"],
        key=f"{widget_prefix}_{graph_mode_key}_layout",
    )

    display_row = st.columns([0.8, 0.8, 0.8, 1.0])

    show_edge_labels = display_row[0].checkbox(
        "Show edge labels",
        value=False,
        key=f"{widget_prefix}_{graph_mode_key}_show_edge_labels",
    )

    node_label_max_length = display_row[1].slider(
        "Node label length",
        min_value=8,
        max_value=80,
        value=28,
        step=2,
        key=f"{widget_prefix}_{graph_mode_key}_node_label_length",
    )

    hide_isolated = display_row[2].checkbox(
        "Hide weak/duplicate noise",
        value=True,
        key=f"{widget_prefix}_{graph_mode_key}_hide_noise",
    )

    focus_direction = display_row[3].selectbox(
        "Focus direction",
        ["All edges", "Source contains", "Target contains", "Source or target contains"],
        key=f"{widget_prefix}_{graph_mode_key}_focus_direction",
    )

    advanced_filters = st.expander("Advanced graph filters", expanded=True)

    with advanced_filters:
        filter_a, filter_b, filter_c = st.columns(3)

        source_filter = filter_a.text_input(
            "Source contains",
            placeholder="e.g. FACT, DIM, dbo.Table",
            key=f"{widget_prefix}_{graph_mode_key}_source_contains",
        )

        target_filter = filter_b.text_input(
            "Target contains",
            placeholder="e.g. FACT, DIM, dbo.Table",
            key=f"{widget_prefix}_{graph_mode_key}_target_contains",
        )

        task_filter = filter_c.text_input(
            "Task contains",
            placeholder="e.g. Insert, Load, Aggregate",
            key=f"{widget_prefix}_{graph_mode_key}_task_contains",
        )

        filter_d, filter_e, filter_f = st.columns(3)

        component_filter = filter_d.text_input(
            "Component contains",
            placeholder="Data flow component",
            key=f"{widget_prefix}_{graph_mode_key}_component_contains",
        )

        operation_filter = filter_e.text_input(
            "Operation contains",
            placeholder="read, write, insert, select",
            key=f"{widget_prefix}_{graph_mode_key}_operation_contains",
        )

        confidence_options = []
        if "confidence" in lineage_df.columns:
            confidence_options = sorted(
                lineage_df["confidence"]
                .fillna("")
                .astype(str)
                .str.strip()
                .replace("", pd.NA)
                .dropna()
                .unique()
                .tolist()
            )

        selected_confidence = filter_f.multiselect(
            "Confidence",
            confidence_options,
            default=confidence_options,
            key=f"{widget_prefix}_{graph_mode_key}_confidence",
        )

    graph_df = lineage_df.copy()
    graph_df["source"] = graph_df["source"].fillna("").astype(str).str.strip()
    graph_df["target"] = graph_df["target"].fillna("").astype(str).str.strip()
    graph_df["relationship_type"] = graph_df["relationship_type"].fillna("").astype(str).str.strip()

    def contains_filter(df: pd.DataFrame, column: str, value: str) -> pd.DataFrame:
        if not value.strip() or column not in df.columns:
            return df

        return df[
            df[column]
            .fillna("")
            .astype(str)
            .str.contains(value.strip(), case=False, regex=False)
        ]


    def contains_any_filter(df: pd.DataFrame, columns: list[str], value: str) -> pd.DataFrame:
        if not value.strip():
            return df

        available_columns = [column for column in columns if column in df.columns]
        if not available_columns:
            return df

        searchable = (
            df[available_columns]
            .fillna("")
            .astype(str)
            .agg(" ".join, axis=1)
            .str.lower()
        )

        return df[searchable.str.contains(value.strip().lower(), regex=False)]

    graph_df = graph_df[
        (graph_df["source"] != "")
        & (graph_df["target"] != "")
        & (graph_df["source"] != graph_df["target"])
    ]

    # if selected_types:
    #     graph_df = graph_df[graph_df["relationship_type"].isin(selected_types)]

    # if search_text.strip():
    #     needle = search_text.strip().lower()
    #     searchable_columns = [
    #         "source",
    #         "target",
    #         "relationship_type",
    #         "task_name",
    #         "component_name",
    #         "source_object",
    #         "target_object",
    #         "source_column",
    #         "target_column",
    #         "operation",
    #         "expression",
    #     ]

    if selected_types:
        graph_df = graph_df[graph_df["relationship_type"].isin(selected_types)]

    if selected_confidence and "confidence" in graph_df.columns:
        graph_df = graph_df[
            graph_df["confidence"]
            .fillna("")
            .astype(str)
            .str.strip()
            .isin(selected_confidence)
        ]

    if source_filter.strip():
        graph_df = contains_any_filter(
            graph_df,
            ["source", "source_object", "source_column"],
            source_filter,
        )

    if target_filter.strip():
        graph_df = contains_any_filter(
            graph_df,
            ["target", "target_object", "target_column"],
            target_filter,
        )

    if task_filter.strip():
        graph_df = contains_any_filter(
            graph_df,
            ["task_name", "source", "target"],
            task_filter,
        )

    if component_filter.strip():
        graph_df = contains_any_filter(
            graph_df,
            ["component_name", "source", "target"],
            component_filter,
        )

    if operation_filter.strip():
        graph_df = contains_any_filter(
            graph_df,
            ["operation", "expression", "relationship_type"],
            operation_filter,
        )

    if search_text.strip():
        graph_df = contains_any_filter(
            graph_df,
            [
                "source",
                "target",
                "relationship_type",
                "task_name",
                "component_name",
                "source_object",
                "target_object",
                "source_column",
                "target_column",
                "operation",
                "expression",
            ],
            search_text,
        )

    # if focus_direction != "All edges" and search_text.strip():
    #     focus_value = search_text.strip()

    #     if focus_direction == "Source contains":
    #         graph_df = contains_any_filter(graph_df, ["source", "source_object", "source_column"], focus_value)

    #     elif focus_direction == "Target contains":
    #         graph_df = contains_any_filter(graph_df, ["target", "target_object", "target_column"], focus_value)

    #     elif focus_direction == "Source or target contains":
    #         source_matches = contains_any_filter(
    #             graph_df,
    #             ["source", "source_object", "source_column"],
    #             focus_value,
    #         )
    #         target_matches = contains_any_filter(
    #             graph_df,
    #             ["target", "target_object", "target_column"],
    #             focus_value,
    #         )
    #         graph_df = pd.concat([source_matches, target_matches]).drop_duplicates()

    #     available_columns = [column for column in searchable_columns if column in graph_df.columns]

    #     searchable = (
    #         graph_df[available_columns]
    #         .fillna("")
    #         .astype(str)
    #         .agg(" ".join, axis=1)
    #         .str.lower()
    #     )

    #     graph_df = graph_df[searchable.str.contains(needle, regex=False)]

    if focus_direction != "All edges" and search_text.strip():
        focus_value = search_text.strip()

        if focus_direction == "Source contains":
            graph_df = contains_any_filter(
                graph_df,
                ["source", "source_object", "source_column"],
                focus_value,
            )

        elif focus_direction == "Target contains":
            graph_df = contains_any_filter(
                graph_df,
                ["target", "target_object", "target_column"],
                focus_value,
            )

        elif focus_direction == "Source or target contains":
            source_matches = contains_any_filter(
                graph_df,
                ["source", "source_object", "source_column"],
                focus_value,
            )
            target_matches = contains_any_filter(
                graph_df,
                ["target", "target_object", "target_column"],
                focus_value,
            )
            graph_df = pd.concat([source_matches, target_matches]).drop_duplicates()

    dedupe_columns = [
        column for column in [
            "source",
            "target",
            "relationship_type",
            "task_name",
            "component_name",
            "source_object",
            "target_object",
            "source_column",
            "target_column",
            "operation",
        ]
        if column in graph_df.columns
    ]


    if hide_isolated:
        graph_df = graph_df.drop_duplicates(subset=dedupe_columns)

    total_matching_edges = len(graph_df)
    graph_df = graph_df.head(edge_limit)
    
    if graph_df.empty:
        st.warning("No graph edges match the selected filters.")
        return

    def clean_graph_value(value: object) -> str:
        return str(value or "").strip()

    def short_graph_label(value: str, max_length: int | None = None) -> str:
        value = clean_graph_value(value)

        max_length = max_length or node_label_max_length

        if len(value) <= max_length:
            return value

        keep = max(4, max_length // 2 - 1)
        return f"{value[:keep]}…{value[-keep:]}"

    def edge_value(row: pd.Series, column: str) -> str:
        if column not in row:
            return ""
        return clean_graph_value(row.get(column, ""))

    def infer_node_kind(raw_name: str, row: pd.Series, side: str) -> str:
        relationship_type = edge_value(row, "relationship_type").lower()
        raw_lower = raw_name.lower()

        if relationship_type == "column_mapping":
            return "Column"

        if relationship_type == "precedence_constraint":
            return "Task"

        if side == "source":
            if edge_value(row, "source_column") and raw_name == edge_value(row, "source_column"):
                return "Column"
            if edge_value(row, "source_object") and raw_name == edge_value(row, "source_object"):
                return "Table/Object"

        if side == "target":
            if edge_value(row, "target_column") and raw_name == edge_value(row, "target_column"):
                return "Column"
            if edge_value(row, "target_object") and raw_name == edge_value(row, "target_object"):
                return "Table/Object"

        if raw_lower.endswith(".dtsx"):
            return "Package"

        if "task" in raw_lower or relationship_type in {"data_flow_path", "sql_object_lineage"}:
            if "dbo." not in raw_lower and "table" not in raw_lower and "." not in raw_lower:
                return "Task/Component"

        if "." in raw_name:
            return "Table/Object"

        return "Object"

    def stable_node_id(kind: str, raw_name: str) -> str:
        digest = hashlib.sha1(f"{kind}|{raw_name}".encode("utf-8")).hexdigest()[:16]
        return f"{kind}:{digest}"

    def relationship_label(value: str) -> str:
        value = clean_graph_value(value)
        if not value:
            return "LINEAGE"
        return value.upper().replace(" ", "_")

    node_lookup: dict[str, Node] = {}
    node_metadata: list[dict[str, str]] = []
    edges: list[Edge] = []

    for index, row in graph_df.iterrows():
        source_raw = clean_graph_value(row.get("source", ""))
        target_raw = clean_graph_value(row.get("target", ""))

        if not source_raw or not target_raw:
            continue

        source_kind = infer_node_kind(source_raw, row, "source")
        target_kind = infer_node_kind(target_raw, row, "target")

        source_id = stable_node_id(source_kind, source_raw)
        target_id = stable_node_id(target_kind, target_raw)

        for node_id, raw_name, kind in [
            (source_id, source_raw, source_kind),
            (target_id, target_raw, target_kind),
        ]:
            if node_id not in node_lookup:
                if kind == "Column":
                    size = 15
                    shape = "box"
                elif kind == "Task":
                    size = 26
                    shape = "ellipse"
                elif kind == "Task/Component":
                    size = 24
                    shape = "ellipse"
                elif kind == "Package":
                    size = 32
                    shape = "diamond"
                else:
                    size = 22
                    shape = "dot"

                node_lookup[node_id] = Node(
                    id=node_id,
                    label=short_graph_label(raw_name),
                    title=f"{kind}: {raw_name}",
                    size=size,
                    shape=shape,
                    group=kind,
                )

                node_metadata.append(
                    {
                        "node_id": node_id,
                        "label": raw_name,
                        "kind": kind,
                    }
                )

        rel_type = edge_value(row, "relationship_type") or "lineage"
        task_name = edge_value(row, "task_name")
        component_name = edge_value(row, "component_name")
        operation = edge_value(row, "operation")
        confidence = edge_value(row, "confidence")
        expression = edge_value(row, "expression")

        edge_title_parts = [
            f"{source_raw} → {target_raw}",
            f"Relationship: {rel_type}",
        ]

        if task_name:
            edge_title_parts.append(f"Task: {task_name}")
        if component_name:
            edge_title_parts.append(f"Component: {component_name}")
        if operation:
            edge_title_parts.append(f"Operation: {operation}")
        if confidence:
            edge_title_parts.append(f"Confidence: {confidence}")
        if expression:
            edge_title_parts.append(f"Expression: {expression[:300]}")

        # edges.append(
        #     Edge(
        #         source=source_id,
        #         target=target_id,
        #         label=relationship_label(rel_type),
        #         title="<br>".join(edge_title_parts),
        #     )
        # )

        edges.append(
            Edge(
                source=source_id,
                target=target_id,
                label=relationship_label(rel_type) if show_edge_labels else "",
                title="<br>".join(edge_title_parts),
            )
        )



    if not node_lookup or not edges:
        st.warning("No valid graph nodes or edges could be built from the filtered lineage data.")
        return

    st.caption(
        f"Showing {len(edges):,} of {total_matching_edges:,} matching relationship(s) "
        f"across {len(node_lookup):,} node(s)."
    )

    hierarchical = layout_mode == "Hierarchical"

    config = Config(
        width=1200,
        height=850,
        directed=True,
        physics=not hierarchical,
        hierarchical=hierarchical,
        nodeHighlightBehavior=True,
        collapsible=True,
    )

    selected_node = agraph(
        nodes=list(node_lookup.values()),
        edges=edges,
        config=config,
    )

    if selected_node:
        selected = next(
            (node for node in node_metadata if node["node_id"] == selected_node),
            None,
        )
        if selected:
            st.info(f"Selected node: {selected['kind']} — {selected['label']}")

    with st.expander("Graph edge data"):
        st.dataframe(graph_df, use_container_width=True, hide_index=True, height=420)

    with st.expander("Graph node data"):
        st.dataframe(pd.DataFrame(node_metadata), use_container_width=True, hide_index=True, height=360)    

def render_architecture(parsed: dict[str, Any]) -> None:
    st.subheader("Architecture inventory")

    tab_connections, tab_tasks, tab_sql, tab_flows, tab_events = st.tabs(
        ["Connections", "Executables", "SQL Tasks", "Data Flows", "Events & Constraints"]
    )

    with tab_connections:
        st.dataframe(pd.DataFrame(parsed.get("connections", [])), use_container_width=True, hide_index=True)

    with tab_tasks:
        st.dataframe(pd.DataFrame(parsed.get("executables", [])), use_container_width=True, hide_index=True)

    with tab_sql:
        sql_tasks = parsed.get("sql_tasks", [])
        compact = [
            {
                "task_name": task.get("task_name"),
                "operation": task.get("operation"),
                "connection_name": task.get("connection_name"),
                "database_name": task.get("database_name"),
                "targets": ", ".join(task.get("targets", [])),
                "sources": ", ".join(task.get("sources", [])[:12]),
                "source_count": len(task.get("sources", [])),
                "target_count": len(task.get("targets", [])),
            }
            for task in sql_tasks
        ]
        st.dataframe(pd.DataFrame(compact), use_container_width=True, hide_index=True)

    with tab_flows:
        flows = []
        for flow in parsed.get("data_flows", []):
            flows.append(
                {
                    "task_name": flow.get("task_name"),
                    "components": len(flow.get("components", [])),
                    "paths": len(flow.get("paths", [])),
                    "column_mappings": len(flow.get("column_mappings", [])),
                }
            )
        st.dataframe(pd.DataFrame(flows), use_container_width=True, hide_index=True)

        flow_names = [flow.get("task_name", "") for flow in parsed.get("data_flows", [])]
        if flow_names:
            selected_flow = st.selectbox("Inspect data flow", flow_names)
            flow = next((item for item in parsed.get("data_flows", []) if item.get("task_name") == selected_flow), None)
            if flow:
                st.markdown("##### Components")
                st.dataframe(pd.DataFrame(flow.get("components", [])), use_container_width=True, hide_index=True)
                st.markdown("##### Paths")
                st.dataframe(pd.DataFrame(flow.get("paths", [])), use_container_width=True, hide_index=True)
                st.markdown("##### Column mappings")
                st.dataframe(pd.DataFrame(flow.get("column_mappings", [])), use_container_width=True, hide_index=True)

    with tab_events:
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("##### Precedence constraints")
            st.dataframe(pd.DataFrame(parsed.get("precedence_constraints", [])), use_container_width=True, hide_index=True)
        with col_b:
            st.markdown("##### Event handlers")
            st.dataframe(pd.DataFrame(parsed.get("event_handlers", [])), use_container_width=True, hide_index=True)


def render_json(parsed: dict[str, Any]) -> None:
    st.subheader("Parsed JSON")
    option = st.radio("JSON scope", ["Compact profile", "Full parsed structure"], horizontal=True)

    if option == "Compact profile":
        compact = {
            "source_path": parsed.get("source_path"),
            "sha256": parsed.get("sha256"),
            "package": parsed.get("package"),
            "counts": package_profile(
                parsed,
                pd.DataFrame(parsed.get("metadata_rows", [])),
                pd.DataFrame(parsed.get("lineage_edges", [])),
            ),
            "connections": parsed.get("connections"),
            "data_flows": [
                {
                    "task_name": flow.get("task_name"),
                    "components": len(flow.get("components", [])),
                    "paths": len(flow.get("paths", [])),
                    "column_mappings": len(flow.get("column_mappings", [])),
                }
                for flow in parsed.get("data_flows", [])
            ],
        }
        st.json(compact, expanded=2)
    else:
        st.json(parsed, expanded=1)


def package_profile(parsed: dict[str, Any], metadata_df: pd.DataFrame, lineage_df: pd.DataFrame) -> dict[str, Any]:
    return {
        "connections": len(parsed.get("connections", [])),
        "configurations": len(parsed.get("configurations", [])),
        "variables": len(parsed.get("variables", [])),
        "executables": len(parsed.get("executables", [])),
        "sql_tasks": len(parsed.get("sql_tasks", [])),
        "data_flows": len(parsed.get("data_flows", [])),
        "precedence_constraints": len(parsed.get("precedence_constraints", [])),
        "event_handlers": len(parsed.get("event_handlers", [])),
        "metadata_rows": int(len(metadata_df)),
        "lineage_edges": int(len(lineage_df)),
    }


def build_sankey(edges: pd.DataFrame, font_size: int = 17, label_max_length: int = 56) -> go.Figure:
    clean_edges = edges.copy()
    clean_edges["source"] = clean_edges["source"].fillna("").astype(str).str.strip()
    clean_edges["target"] = clean_edges["target"].fillna("").astype(str).str.strip()
    clean_edges = clean_edges[(clean_edges["source"] != "") & (clean_edges["target"] != "")]
    clean_edges = clean_edges[clean_edges["source"] != clean_edges["target"]]

    nodes = pd.unique(pd.concat([clean_edges["source"], clean_edges["target"]], ignore_index=True)).tolist()
    node_lookup = {node: index for index, node in enumerate(nodes)}
    display_labels = [shorten_sankey_label(node, label_max_length) for node in nodes]

    grouped = (
        clean_edges.groupby(["source", "target"], dropna=False)
        .size()
        .reset_index(name="value")
        .sort_values("value", ascending=False)
    )

    link_hover = [
        f"{row.source} → {row.target}<br>Edges: {row.value}"
        for row in grouped.itertuples()
    ]

    figure = go.Figure(
        data=[
            go.Sankey(
                arrangement="snap",
                node={
                    "label": display_labels,
                    "customdata": nodes,
                    "pad": max(22, font_size + 8),
                    "thickness": max(24, int(font_size * 1.55)),
                    "line": {"color": "rgba(40,40,40,0.65)", "width": 0.8},
                    "hovertemplate": "<b>%{customdata}</b><extra></extra>",
                },
                link={
                    "source": grouped["source"].map(node_lookup).tolist(),
                    "target": grouped["target"].map(node_lookup).tolist(),
                    "value": grouped["value"].tolist(),
                    "customdata": link_hover,
                    "color": ["rgba(95,95,95,0.28)"] * len(grouped),
                    "hovertemplate": "%{customdata}<extra></extra>",
                },
            )
        ]
    )
    figure.update_layout(
        height=sankey_chart_height(len(nodes), len(grouped)),
        font={
            "size": font_size,
            "color": "#111111",
            "family": "Arial, Helvetica, sans-serif",
        },
        paper_bgcolor="white",
        plot_bgcolor="white",
        margin={"l": 35, "r": 35, "t": 20, "b": 20},
    )
    return figure


def sankey_chart_height(node_count: int, edge_count: int) -> int:
    return min(max(880, node_count * 30 + edge_count * 3 + 220), 2400)


def shorten_sankey_label(value: Any, max_length: int = 56) -> str:
    text = str(value or "").strip()
    if len(text) <= max_length:
        return text

    if max_length < 12:
        return text[:max_length]

    left_size = max(8, int(max_length * 0.42))
    right_size = max(8, max_length - left_size - 1)
    return f"{text[:left_size]}…{text[-right_size:]}"


@st.cache_data(show_spinner=False)
def cached_llm_summary(summary_payload: str, endpoint_name: str) -> str:
    try:
        from databricks_openai import DatabricksOpenAI
    except Exception as exc:
        raise RuntimeError(f"databricks-openai is not available: {exc}") from exc

    client = DatabricksOpenAI()
    response = client.chat.completions.create(
        model=endpoint_name,
        messages=[
            {
                "role": "system",
                "content": "You summarize SQL Agent SSIS DTSX metadata for data engineering stakeholders. Produce one concise paragraph only.",
            },
            {
                "role": "user",
                "content": summary_payload,
            },
        ],
        temperature=0.1,
        max_tokens=220,
    )
    return response.choices[0].message.content.strip()


@st.cache_data(show_spinner=False)
def cached_llm_job_error_analysis(error_payload: str, endpoint_name: str) -> str:
    try:
        from databricks_openai import DatabricksOpenAI
    except Exception as exc:
        raise RuntimeError(f"databricks-openai is not available: {exc}") from exc

    client = DatabricksOpenAI()
    response = client.chat.completions.create(
        model=endpoint_name,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a senior SQL Server Agent, SSIS, and SQL Server DBA production support lead. "
                    "Analyze only the supplied job-history rows and do not invent servers, paths, package names, credentials, or table names that are not present. "
                    "Return detailed Markdown with exactly four sections: "
                    "### Error overview, ### Root-cause interpretation, ### Steps to fix, and ### Validation checklist. "
                    "In Error overview, write two to four specific paragraphs that mention the affected server, job, step, run date, environment, category, error code or SQLSTATE when available, and the key failure message. "
                    "In Root-cause interpretation, explain the likely failure mechanism and explicitly state confidence as High, Medium, or Low. "
                    "In Steps to fix, provide six to ten practical numbered actions with concrete SQL Agent, SSIS, SQL Server, filesystem, credential, connection manager, package deployment, and retry checks as applicable to the error. "
                    "In Validation checklist, provide concise bullets the operator can use before rerunning the job. "
                    "Be diagnostic and operational, not generic. Preserve uncertainty where evidence is missing."
                ),
            },
            {
                "role": "user",
                "content": error_payload,
            },
        ],
        temperature=0.1,
        max_tokens=2200,
    )
    return response.choices[0].message.content.strip()


def generate_or_fallback_job_error_analysis(filtered_errors: pd.DataFrame, endpoint_name: str) -> str:
    payload = build_job_error_payload(filtered_errors)
    fallback = deterministic_job_error_analysis(filtered_errors)

    if not endpoint_name.strip():
        return fallback

    try:
        return cached_llm_job_error_analysis(payload, endpoint_name.strip())
    except Exception as exc:
        st.caption(f"LLM error analysis unavailable; using deterministic analysis. Reason: {exc}")
        return fallback


def build_job_error_payload(filtered_errors: pd.DataFrame) -> str:
    safe = filtered_errors.copy()
    rows = []

    selected_columns = [
        "server_name",
        "job_name",
        "step_id_display",
        "step_name",
        "step_label",
        "run_date",
        "environment",
        "error_category",
        "error_code",
        "sql_state",
        "executed_as",
        "message",
        "message_excerpt",
    ]

    available_columns = [column for column in selected_columns if column in safe.columns]

    for row in safe.head(40)[available_columns].to_dict(orient="records"):
        full_message = clean_cell(row.get("message", ""))
        rows.append(
            {
                "server_name": clean_cell(row.get("server_name", "")),
                "job_name": clean_cell(row.get("job_name", "")),
                "step_id": clean_cell(row.get("step_id_display", "")),
                "step_name": clean_cell(row.get("step_name", "")),
                "step_label": clean_cell(row.get("step_label", "")),
                "run_date": clean_cell(row.get("run_date", "")),
                "environment": clean_cell(row.get("environment", "")),
                "error_category": clean_cell(row.get("error_category", "")),
                "error_code": clean_cell(row.get("error_code", "")),
                "sql_state": clean_cell(row.get("sql_state", "")),
                "executed_as": clean_cell(row.get("executed_as", "")),
                "full_message": full_message[:3000],
                "message_excerpt": clean_cell(row.get("message_excerpt", "")),
            }
        )

    category_counts = (
        safe.groupby("error_category", dropna=False)
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
        .to_dict(orient="records")
    )

    step_counts = (
        safe.groupby(["server_name", "job_name", "step_label", "error_category"], dropna=False)
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
        .head(20)
        .to_dict(orient="records")
    )

    payload = {
        "instructions": {
            "analysis_depth": "detailed production-support analysis",
            "must_include": [
                "affected server/job/step/date/environment",
                "error category and available code or SQLSTATE",
                "likely root cause with confidence",
                "concrete remediation actions",
                "validation checklist before rerun",
            ],
            "avoid": [
                "generic statements without tying them to the error message",
                "invented credentials, paths, tables, package names, or infrastructure",
            ],
        },
        "row_count": int(len(safe)),
        "servers": unique_sorted(safe["server_name"]) if "server_name" in safe.columns else [],
        "jobs": unique_sorted(safe["job_name"]) if "job_name" in safe.columns else [],
        "steps": unique_sorted(safe["step_label"]) if "step_label" in safe.columns else [],
        "run_dates": unique_sorted(safe["run_date"]) if "run_date" in safe.columns else [],
        "environments": unique_sorted(safe["environment"]) if "environment" in safe.columns else [],
        "category_counts": category_counts,
        "step_error_counts": step_counts,
        "error_rows": rows,
    }
    return json.dumps(payload, ensure_ascii=False)[:30000]

def deterministic_job_error_analysis(filtered_errors: pd.DataFrame) -> str:
    categories = filtered_errors["error_category"].value_counts().to_dict()
    jobs = ", ".join(unique_sorted(filtered_errors["job_name"])[:5])
    steps = ", ".join(unique_sorted(filtered_errors["step_label"])[:5])
    servers = ", ".join(unique_sorted(filtered_errors["server_name"])[:5])
    dates = ", ".join(unique_sorted(filtered_errors["run_date"])[:5])
    category_text = ", ".join([f"{category}: {count}" for category, count in categories.items()])

    sample_message = ""
    if "message" in filtered_errors.columns and not filtered_errors.empty:
        sample_message = clean_cell(filtered_errors["message"].iloc[0])
    if not sample_message and "message_excerpt" in filtered_errors.columns and not filtered_errors.empty:
        sample_message = clean_cell(filtered_errors["message_excerpt"].iloc[0])

    root_cause_notes = []
    remediation_steps = []
    validation_checks = []

    category_set = set(categories)

    if "Schema mismatch" in category_set:
        root_cause_notes.append("The SQL Agent step is likely failing because the SSIS package or SQL task is inserting/selecting a different number of columns than the target table definition expects.")
        remediation_steps.extend(
            [
                "Open the failing package and identify the Execute SQL Task or Data Flow component referenced by the step message.",
                "Compare the target table column list with the package column mappings and any INSERT...SELECT statement used by the task.",
                "Check for recent DDL changes on the target table, especially added non-null columns without defaults, reordered insert lists, or removed columns.",
                "Correct the SQL statement or package mapping so the number, order, and data types of source columns match the destination.",
            ]
        )
        validation_checks.extend(
            [
                "Run the failing SQL statement or data-flow validation against a non-production connection.",
                "Confirm target table schema matches the package version that is deployed.",
            ]
        )

    if "SSIS protection/decryption" in category_set:
        root_cause_notes.append("The package likely contains protected sensitive properties that the SQL Agent execution identity cannot decrypt.")
        remediation_steps.extend(
            [
                "Check the package ProtectionLevel and whether it depends on a user key from the original developer or deployment account.",
                "Redeploy the package using a server-safe protection level such as DontSaveSensitive with environment/project parameters or SSIS catalog environment variables.",
                "Validate the SQL Agent proxy or service account has access to any external configuration, connection secrets, and SSIS catalog environment references.",
            ]
        )
        validation_checks.extend(
            [
                "Validate the package under the SQL Agent proxy account, not only under your personal account.",
                "Confirm sensitive connection properties are supplied from approved parameters/secrets at runtime.",
            ]
        )

    if "Remote server/login configuration" in category_set:
        root_cause_notes.append("The job is likely failing because a linked or remote SQL Server login mapping, network path, or remote access setting is unavailable to the execution account.")
        remediation_steps.extend(
            [
                "Test connectivity from the SQL Agent host to the remote SQL Server or file server named in the error.",
                "Validate linked server security mappings, remote login settings, DNS resolution, firewall rules, and service account permissions.",
                "Confirm the job owner, proxy, and SQL Agent service account have the expected access path.",
            ]
        )
        validation_checks.extend(
            [
                "Run a minimal connectivity query or file access test from the SQL Agent host.",
                "Confirm the remote login mapping uses the intended credential.",
            ]
        )

    if "Package load failure" in category_set:
        root_cause_notes.append("The package could not be loaded from the referenced package store, filesystem path, or SSIS catalog location.")
        remediation_steps.extend(
            [
                "Confirm the DTSX package exists at the path referenced by the SQL Agent step.",
                "Check package filename casing, extension, folder location, and deployment target.",
                "Validate the runtime version and provider dependencies are compatible with the package version.",
                "Confirm the SQL Agent proxy account can read the package and all referenced configuration files.",
            ]
        )
        validation_checks.extend(
            [
                "Open or validate the package from the server where SQL Agent runs.",
                "Confirm the package path in the job step matches the deployed location.",
            ]
        )

    if "OLE DB connection failure" in category_set:
        root_cause_notes.append("The package is likely failing while opening an OLE DB connection or dynamic connection manager.")
        remediation_steps.extend(
            [
                "Identify the connection manager named in the error message and test its server, database, authentication mode, and provider.",
                "Check password rotation, disabled logins, expired accounts, unavailable databases, and provider installation on the SQL Agent host.",
                "Validate any dynamic connection string expression resolves to the expected server and database at runtime.",
                "Review SQL Server error logs around the failure timestamp for login failures or provider errors.",
            ]
        )
        validation_checks.extend(
            [
                "Test the connection manager with the same execution account used by SQL Agent.",
                "Confirm the resolved connection string is correct for the selected environment.",
            ]
        )

    if "Missing file or executable" in category_set:
        root_cause_notes.append("The job likely references a package, script, executable, folder, or input file that is missing from the SQL Agent execution host.")
        remediation_steps.extend(
            [
                "Check every filesystem path in the job step command and package configuration from the SQL Agent host.",
                "Validate UNC share permissions for the SQL Agent proxy or service account.",
                "Confirm scheduled upstream file drops completed before this job started.",
                "Add preflight checks for required files before package execution.",
            ]
        )
        validation_checks.extend(
            [
                "List the referenced directory from the SQL Agent host using the same service/proxy account.",
                "Confirm the required input file or executable exists before rerunning.",
            ]
        )

    if "Execution timeout" in category_set:
        root_cause_notes.append("The failure likely occurred because a query, package task, or external operation exceeded its configured timeout or was blocked.")
        remediation_steps.extend(
            [
                "Review query duration, blocking, deadlocks, destination indexes, and transaction log pressure during the job window.",
                "Check SSIS task timeout settings, SQL command timeout values, and SQL Agent job-step timeout configuration.",
                "Tune the long-running statement or split the load into smaller batches if needed.",
                "Avoid simply increasing timeout until blocking and query plan regressions are reviewed.",
            ]
        )
        validation_checks.extend(
            [
                "Check wait stats, blocking chains, and job runtime history around the failure.",
                "Rerun during a controlled window and monitor task duration.",
            ]
        )

    if "Execute SQL task failure" in category_set:
        root_cause_notes.append("The failing step likely reached an Execute SQL Task that returned an error from SQL Server or from a stored procedure.")
        remediation_steps.extend(
            [
                "Extract the SQL statement or stored procedure from the package task and run it manually with the same parameters.",
                "Check object existence, permissions, temp table dependencies, transaction handling, and parameter values.",
                "Review the first SQL error before the final 'The step failed' message because later messages are usually secondary.",
            ]
        )
        validation_checks.extend(
            [
                "Validate the SQL task succeeds with the same connection and parameter values.",
                "Confirm required database objects exist in the target environment.",
            ]
        )

    if "Package execution failed" in category_set or not remediation_steps:
        root_cause_notes.append("The SQL Agent history shows a package-level failure; the first detailed error before the final failure line should be treated as the root-cause clue.")
        remediation_steps.extend(
            [
                "Open the detailed SQL Agent history and SSIS execution report for the same run timestamp.",
                "Find the first error in chronological order, not the final package failure summary.",
                "Validate the execution account, package path, package parameters, connection managers, and environment-specific configuration.",
                "After applying the fix, rerun the single failing step or package first before enabling the full job chain.",
            ]
        )
        validation_checks.extend(
            [
                "Confirm the package validates successfully before execution.",
                "Confirm the rerun generates no new SQL Agent or SSIS catalog errors.",
            ]
        )

    root_cause_text = " ".join(dict.fromkeys(root_cause_notes))
    remediation_steps = list(dict.fromkeys(remediation_steps))
    validation_checks = list(dict.fromkeys(validation_checks))

    return (
        "### Error overview\n"
        f"The selected history scope contains **{len(filtered_errors)} error row(s)** on server(s) **{servers or 'n/a'}**, "
        f"job(s) **{jobs or 'n/a'}**, and step(s) **{steps or 'n/a'}**"
        f"{f' for run date(s) **{dates}**' if dates else ''}. "
        f"The detected error category distribution is **{category_text or 'n/a'}**. "
        f"The representative message begins: `{sample_message[:500]}`\n\n"
        "### Root-cause interpretation\n"
        f"{root_cause_text or 'The available rows do not contain enough detail to determine a single root cause. Treat the first detailed SQL Agent or SSIS error as the root-cause line and the final package failure as a symptom.'} "
        "Confidence: **Medium** based on categorized SQL Agent message text.\n\n"
        "### Steps to fix\n"
        + "\n".join([f"{index}. {item}" for index, item in enumerate(remediation_steps[:10], start=1)])
        + "\n\n### Validation checklist\n"
        + "\n".join([f"- {item}" for item in validation_checks[:8]])
    )

def generate_or_fallback_summary(parsed: dict[str, Any], endpoint_name: str) -> str:
    payload = build_summary_payload(parsed)
    fallback = deterministic_summary(parsed)

    if not endpoint_name.strip():
        return fallback

    try:
        return cached_llm_summary(payload, endpoint_name.strip())
    except Exception as exc:
        st.caption(f"LLM summary unavailable; using deterministic summary. Reason: {exc}")
        return fallback


def deterministic_summary(parsed: dict[str, Any]) -> str:
    profile = package_profile(
        parsed,
        pd.DataFrame(parsed.get("metadata_rows", [])),
        pd.DataFrame(parsed.get("lineage_edges", [])),
    )
    package_name = parsed.get("package", {}).get("name", "This DTSX package")
    connection_names = ", ".join([item.get("name", "") for item in parsed.get("connections", []) if item.get("name")])
    return (
        f"{package_name} contains {profile['executables']} control-flow executables, "
        f"{profile['sql_tasks']} Execute SQL tasks, {profile['data_flows']} Data Flow tasks, "
        f"{profile['connections']} connection managers, {profile['variables']} variables, and "
        f"{profile['lineage_edges']} detected lineage relationships. The package references connections "
        f"{connection_names or 'not explicitly named'} and exposes SQL, data-flow component, path, and column-level metadata in the standard metadata table."
    )


def build_summary_payload(parsed: dict[str, Any]) -> str:
    sql_tasks = parsed.get("sql_tasks", [])
    data_flows = parsed.get("data_flows", [])
    payload = {
        "package": parsed.get("package", {}),
        "counts": package_profile(
            parsed,
            pd.DataFrame(parsed.get("metadata_rows", [])),
            pd.DataFrame(parsed.get("lineage_edges", [])),
        ),
        "connections": [
            {
                "name": item.get("name"),
                "server_name": item.get("server_name"),
                "database_name": item.get("database_name"),
                "provider": item.get("provider"),
            }
            for item in parsed.get("connections", [])
        ],
        "sql_tasks": [
            {
                "task_name": item.get("task_name"),
                "operation": item.get("operation"),
                "targets": item.get("targets", [])[:6],
                "sources": item.get("sources", [])[:10],
            }
            for item in sql_tasks[:12]
        ],
        "data_flows": [
            {
                "task_name": flow.get("task_name"),
                "component_count": len(flow.get("components", [])),
                "path_count": len(flow.get("paths", [])),
                "column_mapping_count": len(flow.get("column_mappings", [])),
            }
            for flow in data_flows
        ],
    }
    return json.dumps(payload, ensure_ascii=False)[:12000]


if __name__ == "__main__":
    main()
