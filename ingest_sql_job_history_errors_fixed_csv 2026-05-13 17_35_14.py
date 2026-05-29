# Databricks notebook source
# MAGIC %md
# MAGIC # Ingest SQL Agent job history errors
# MAGIC
# MAGIC This notebook prepares SQL Agent job-history error data for the Streamlit lineage app.
# MAGIC It reads the job history CSV from the Unity Catalog volume, normalizes the fields, writes a Delta table, and writes a read-optimized normalized CSV back to the volume.

# COMMAND ----------

dbutils.widgets.text("catalog_name", "btris_dbx")
dbutils.widgets.text("schema_name", "ssis_lineage")
dbutils.widgets.text("volume_name", "dtsx_packages")
dbutils.widgets.text("metadata_folder", "metadata")
dbutils.widgets.text("source_history_file", "sqljobshistory.csv")
dbutils.widgets.text("normalized_history_file", "sqljobshistory_normalized.csv")
dbutils.widgets.text("table_name", "sql_job_history_errors")

catalog_name = dbutils.widgets.get("catalog_name").strip()
schema_name = dbutils.widgets.get("schema_name").strip()
volume_name = dbutils.widgets.get("volume_name").strip()
metadata_folder = dbutils.widgets.get("metadata_folder").strip().strip("/")
source_history_file = dbutils.widgets.get("source_history_file").strip().strip("/")
normalized_history_file = dbutils.widgets.get("normalized_history_file").strip().strip("/")
table_name = dbutils.widgets.get("table_name").strip()

volume_path = f"/Volumes/{catalog_name}/{schema_name}/{volume_name}"
metadata_path = f"{volume_path}/{metadata_folder}"
source_history_path = source_history_file if source_history_file.startswith("/Volumes/") else f"{metadata_path}/{source_history_file}"
normalized_history_path = f"{metadata_path}/{normalized_history_file}"
schema_fqn = f"`{catalog_name}`.`{schema_name}`"
volume_fqn = f"`{catalog_name}`.`{schema_name}`.`{volume_name}`"
table_fqn = f"`{catalog_name}`.`{schema_name}`.`{table_name}`"

spark.createDataFrame(
    [
        ("source_history_path", source_history_path),
        ("normalized_history_path", normalized_history_path),
        ("history_table", table_fqn),
        ("metadata_path", metadata_path),
    ],
    ["setting", "value"],
).display()

# COMMAND ----------

import re

def validate_uc_name(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise ValueError(f"{label} is not a valid Unity Catalog object name: {value}")
    return value

catalog_name = validate_uc_name(catalog_name, "catalog_name")
schema_name = validate_uc_name(schema_name, "schema_name")
volume_name = validate_uc_name(volume_name, "volume_name")
table_name = validate_uc_name(table_name, "table_name")

spark.sql(f"CREATE SCHEMA IF NOT EXISTS {schema_fqn}")
spark.sql(f"CREATE VOLUME IF NOT EXISTS {volume_fqn}")
dbutils.fs.mkdirs(metadata_path)

spark.createDataFrame(
    [
        ("schema", schema_fqn, "ready"),
        ("volume", volume_fqn, "ready"),
        ("metadata_folder", metadata_path, "ready"),
    ],
    ["object_type", "object_name_or_path", "status"],
).display()

# COMMAND ----------

from pathlib import Path

def local_volume_path(path: str) -> str:
    return path.replace("dbfs:", "", 1)

if not source_history_path.lower().endswith((".csv", ".xlsx")):
    raise ValueError("source_history_file must point to a .csv or .xlsx file")

if source_history_path.lower().endswith(".csv"):
    raw_history = (
        spark.read
        .option("header", True)
        .option("multiLine", True)
        .option("quote", '"')
        .option("escape", '"')
        .option("mode", "PERMISSIVE")
        .csv(source_history_path)
    )
else:
    try:
        import pandas as pd
        raw_pdf = pd.read_excel(local_volume_path(source_history_path)).astype(str)
        raw_history = spark.createDataFrame(raw_pdf)
    except Exception as exc:
        raise RuntimeError(
            "The source file is .xlsx, but this cluster could not read Excel. "
            "Export the workbook to CSV and upload it to the metadata folder, then rerun with source_history_file=sqljobshistory.csv."
        ) from exc

raw_history.limit(20).display()

# COMMAND ----------

import re
from pyspark.sql import functions as F

def normalize_column_name(value: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", str(value).strip().lower()).strip("_")

def first_existing_column(columns: list[str], *candidates: str) -> str:
    for candidate in candidates:
        if candidate in columns:
            return candidate
    return ""

normalized_names = [normalize_column_name(column) for column in raw_history.columns]
history_raw = raw_history.toDF(*normalized_names)
available_columns = history_raw.columns

server_column = first_existing_column(available_columns, "server_name", "servername", "servername1", "server")
job_column = first_existing_column(available_columns, "job_name", "jobname", "jobname1")
step_id_column = first_existing_column(available_columns, "step_id", "stepid")
step_name_column = first_existing_column(available_columns, "step_name", "stepname")
run_date_column = first_existing_column(available_columns, "run_date", "rundate")
message_column = first_existing_column(available_columns, "message", "error_message", "job_message")
environment_column = first_existing_column(available_columns, "environment", "env")

required_column_map = {
    "server_name": server_column,
    "job_name": job_column,
    "step_id": step_id_column,
    "step_name": step_name_column,
    "run_date": run_date_column,
    "message": message_column,
}

missing = [name for name, source in required_column_map.items() if not source]
if missing:
    raise ValueError(f"Job history file is missing required column(s): {', '.join(missing)}")

environment_expr = F.col(environment_column).cast("string") if environment_column else F.lit("")

base_history = history_raw.select(
    F.trim(F.coalesce(F.col(server_column).cast("string"), F.lit(""))).alias("server_name"),
    F.trim(F.coalesce(F.col(job_column).cast("string"), F.lit(""))).alias("job_name"),
    F.trim(F.coalesce(F.col(step_id_column).cast("string"), F.lit(""))).alias("step_id_raw"),
    F.trim(F.coalesce(F.col(step_name_column).cast("string"), F.lit(""))).alias("step_name"),
    F.trim(F.coalesce(F.col(run_date_column).cast("string"), F.lit(""))).alias("run_date_raw"),
    F.trim(F.coalesce(environment_expr, F.lit(""))).alias("environment"),
    F.trim(F.coalesce(F.col(message_column).cast("string"), F.lit(""))).alias("message"),
).where(F.col("message") != "")

step_id_number = F.col("step_id_raw").cast("double")
run_date_number = F.col("run_date_raw").cast("double")

run_date_digits = F.regexp_replace(
    F.when(run_date_number.isNotNull(), F.format_string("%.0f", run_date_number)).otherwise(F.col("run_date_raw")),
    "[^0-9]",
    "",
)

message_lower = F.lower(F.col("message"))

history_normalized = (
    base_history
    .withColumn("server_name", F.when(F.col("server_name") == "", F.lit("UNKNOWN_SERVER")).otherwise(F.col("server_name")))
    .withColumn("job_name", F.when(F.col("job_name") == "", F.lit("UNKNOWN_JOB")).otherwise(F.col("job_name")))
    .withColumn("step_id", F.when(step_id_number.isNotNull(), F.format_string("%.0f", step_id_number)).otherwise(F.col("step_id_raw")))
    .withColumn("step_id_numeric", step_id_number.cast("int"))
    .withColumn("step_label", F.concat_ws(" - ", F.col("step_id"), F.when(F.col("step_name") == "", F.lit("(unnamed step)")).otherwise(F.col("step_name"))))
    .withColumn("run_date_key", F.substring(run_date_digits, 1, 8))
    .withColumn("run_date", F.when(F.length("run_date_key") == 8, F.date_format(F.to_date("run_date_key", "yyyyMMdd"), "yyyy-MM-dd")).otherwise(F.col("run_date_raw")))
    .withColumn(
        "error_category",
        F.when(message_lower.contains("column name or number of supplied values") | message_lower.contains("does not match table definition"), F.lit("Schema mismatch"))
        .when(message_lower.contains("failed to decrypt protected xml node") | message_lower.contains("not authorized to access this information"), F.lit("SSIS protection/decryption"))
        .when(message_lower.contains("could not connect to server") | message_lower.contains("remote logins"), F.lit("Remote server/login configuration"))
        .when(message_lower.contains("could not load package") | message_lower.contains("specified package could not be loaded"), F.lit("Package load failure"))
        .when(message_lower.contains("ole db error") | message_lower.contains("dts_e_oledberror") | message_lower.contains("dynamicconnection"), F.lit("OLE DB connection failure"))
        .when(message_lower.contains("timeout expired") | message_lower.contains("timeout period elapsed"), F.lit("Execution timeout"))
        .when(message_lower.contains("system cannot find the file specified") | message_lower.contains("not found") | message_lower.contains("does not exist"), F.lit("Missing file or executable"))
        .when(message_lower.contains("package execution failed"), F.lit("Package execution failed"))
        .when(message_lower.contains("execute sql task") | message_lower.contains("executing the query"), F.lit("Execute SQL task failure"))
        .when(message_lower.contains("process exit code"), F.lit("External process failure"))
        .otherwise(F.lit("Other SQL Agent failure")),
    )
    .withColumn("error_code_hex", F.regexp_extract(F.col("message"), "(?i)\\b(?:Code:\\s*)?(0x[0-9a-f]{8})\\b", 1))
    .withColumn("error_code_number", F.regexp_extract(F.col("message"), "(?i)\\(Error\\s+([0-9]+)\\)", 1))
    .withColumn("error_code", F.when(F.col("error_code_hex") != "", F.col("error_code_hex")).otherwise(F.col("error_code_number")))
    .withColumn("sql_state", F.regexp_extract(F.col("message"), "(?i)SQLSTATE\\s+([A-Z0-9]+)", 1))
    .withColumn("executed_as", F.regexp_extract(F.col("message"), "(?i)Executed as user:\\s*([^\\.]+)\\.", 1))
    .withColumn("message_excerpt", F.when(F.length("message") <= 420, F.col("message")).otherwise(F.concat(F.substring("message", 1, 417), F.lit("..."))))
    .withColumn("message_hash", F.sha2(F.col("message"), 256))
    .withColumn("server_folder", F.lower(F.regexp_replace(F.col("server_name"), "[^A-Za-z0-9_-]+", "_")))
    .drop("step_id_raw", "run_date_raw", "run_date_key", "error_code_hex", "error_code_number")
)

history_normalized.createOrReplaceTempView("job_history_errors_normalized_preview")
history_normalized.display()

# COMMAND ----------

(
    history_normalized
    .write
    .format("delta")
    .mode("overwrite")
    .option("overwriteSchema", "true")
    .saveAsTable(table_fqn)
)

import csv
import pandas as pd
from pathlib import Path

def volume_local_path(path: str) -> str:
    return path.replace("dbfs:", "", 1)

normalized_local_path = Path(volume_local_path(normalized_history_path))
normalized_local_path.parent.mkdir(parents=True, exist_ok=True)

history_pd = history_normalized.toPandas()
history_pd.to_csv(
    normalized_local_path,
    index=False,
    encoding="utf-8",
    quoting=csv.QUOTE_ALL,
    escapechar="\\",
    lineterminator="\n",
)

read_back = pd.read_csv(normalized_local_path)

spark.createDataFrame(
    [
        ("normalized_csv", normalized_history_path),
        ("delta_table", table_fqn),
        ("row_count", str(len(history_pd))),
        ("csv_columns", str(len(history_pd.columns))),
        ("read_back_rows", str(len(read_back))),
    ],
    ["artifact", "value"],
).display()


# COMMAND ----------

summary = (
    history_normalized
    .groupBy("server_name", "job_name", "step_id", "step_name", "error_category")
    .agg(F.count("*").alias("error_count"), F.max("run_date").alias("latest_run_date"))
    .orderBy(F.desc("error_count"), "server_name", "job_name", "step_id")
)

category_summary = (
    history_normalized
    .groupBy("error_category")
    .agg(F.count("*").alias("error_count"))
    .orderBy(F.desc("error_count"))
)

summary.display()
category_summary.display()

print("Job history ingestion completed.")
print("Streamlit app reads normalized history from:")
print(normalized_history_path)
print("Unity Catalog table:")
print(f"{catalog_name}.{schema_name}.{table_name}")