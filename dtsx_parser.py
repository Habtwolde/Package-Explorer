from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from typing import Any


DTS_NAMESPACE = "www.microsoft.com/SqlServer/Dts"
SQL_TASK_NAMESPACE = "www.microsoft.com/sqlserver/dts/tasks/sqltask"


STANDARD_COLUMNS = [
    "package_name",
    "scope",
    "asset_type",
    "object_type",
    "object_name",
    "operation",
    "task_name",
    "component_name",
    "component_class",
    "connection_name",
    "server_name",
    "database_name",
    "schema_name",
    "table_name",
    "source_object",
    "target_object",
    "column_name",
    "data_type",
    "expression",
    "sql_excerpt",
    "ref_id",
]


LINEAGE_COLUMNS = [
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
    "confidence",
    "ref_id",
]


@dataclass(frozen=True)
class SqlObjects:
    operation: str
    targets: list[str]
    sources: list[str]
    insert_columns: list[str]


def parse_dtsx_bytes(content: bytes, source_path: str = "") -> dict[str, Any]:
    parser = DtsxParser(content, source_path)
    return parser.parse()


class DtsxParser:
    def __init__(self, content: bytes, source_path: str = "") -> None:
        self.content = content
        self.source_path = source_path
        self.root = ET.fromstring(content)
        self.parent_map = {child: parent for parent in self.root.iter() for child in parent}
        self.package_name = self.attr(self.root, "ObjectName") or "Package"
        self.connections_by_ref: dict[str, dict[str, Any]] = {}
        self.connections_by_dtsid: dict[str, dict[str, Any]] = {}
        self.component_index: dict[str, dict[str, Any]] = {}
        self.output_column_index: dict[str, dict[str, Any]] = {}
        self.metadata_rows: list[dict[str, Any]] = []
        self.lineage_edges: list[dict[str, Any]] = []
        self.diagnostics: list[dict[str, Any]] = []

    def parse(self) -> dict[str, Any]:
        package = self.parse_package()
        connections = self.parse_connection_managers()
        configurations = self.parse_configurations()
        variables = self.parse_variables()
        executables = self.parse_executables()
        precedence_constraints = self.parse_precedence_constraints()
        event_handlers = self.parse_event_handlers()
        data_flows = self.parse_data_flows()
        sql_tasks = self.parse_sql_tasks()
        self.metadata_rows = self.normalize_rows(self.metadata_rows)
        self.lineage_edges = self.normalize_edges(self.lineage_edges)
        raw_counts = Counter(self.local_name(element.tag) for element in self.root.iter())

        return {
            "source_path": self.source_path,
            "sha256": hashlib.sha256(self.content).hexdigest(),
            "package": package,
            "connections": connections,
            "configurations": configurations,
            "variables": variables,
            "executables": executables,
            "sql_tasks": sql_tasks,
            "data_flows": data_flows,
            "precedence_constraints": precedence_constraints,
            "event_handlers": event_handlers,
            "metadata_rows": self.metadata_rows,
            "lineage_edges": self.lineage_edges,
            "diagnostics": self.diagnostics,
            "raw_counts": dict(sorted(raw_counts.items())),
            "standard_columns": STANDARD_COLUMNS,
            "lineage_columns": LINEAGE_COLUMNS,
        }

    def parse_package(self) -> dict[str, Any]:
        package = {
            "name": self.package_name,
            "ref_id": self.attr(self.root, "refId"),
            "creation_name": self.attr(self.root, "CreationName"),
            "executable_type": self.attr(self.root, "ExecutableType"),
            "description": self.attr(self.root, "Description"),
            "creator_name": self.attr(self.root, "CreatorName"),
            "creator_computer_name": self.attr(self.root, "CreatorComputerName"),
            "creation_date": self.attr(self.root, "CreationDate"),
            "last_modified_product_version": self.attr(self.root, "LastModifiedProductVersion"),
            "locale_id": self.attr(self.root, "LocaleID"),
            "source_path": self.source_path,
        }

        self.add_metadata_row(
            asset_type="package",
            object_type="ssis_package",
            object_name=package["name"],
            operation="package_definition",
            ref_id=package["ref_id"],
        )

        for property_element in self.children(self.root, "Property"):
            property_name = self.attr(property_element, "Name")
            if property_name:
                self.add_metadata_row(
                    asset_type="package",
                    object_type="package_property",
                    object_name=property_name,
                    operation="property",
                    expression=self.text(property_element),
                    ref_id=package["ref_id"],
                )

        return package

    def parse_connection_managers(self) -> list[dict[str, Any]]:
        collection = self.first_child(self.root, "ConnectionManagers")
        connection_elements = self.children(collection, "ConnectionManager") if collection is not None else []

        connections = []
        for element in connection_elements:
            ref_id = self.attr(element, "refId")
            dtsid = self.attr(element, "DTSID")
            name = self.attr(element, "ObjectName") or self.name_from_ref(ref_id)
            inner = self.first_descendant(element, "ConnectionManager", exclude_self=True)
            connection_string = self.attr(inner, "ConnectionString") if inner is not None else self.attr(element, "ConnectionString")
            parsed = parse_connection_string(connection_string)
            connection = {
                "name": name,
                "ref_id": ref_id,
                "dtsid": dtsid,
                "creation_name": self.attr(element, "CreationName"),
                "connection_string": connection_string,
                "server_name": parsed.get("data source", ""),
                "database_name": parsed.get("initial catalog", ""),
                "provider": parsed.get("provider", ""),
                "integrated_security": parsed.get("integrated security", ""),
                "property_expressions": self.parse_property_expressions(element),
            }
            connections.append(connection)

            if ref_id:
                self.connections_by_ref[ref_id] = connection
            if dtsid:
                self.connections_by_dtsid[dtsid] = connection

            self.add_metadata_row(
                asset_type="connection",
                object_type="connection_manager",
                object_name=name,
                operation="connect",
                connection_name=name,
                server_name=connection["server_name"],
                database_name=connection["database_name"],
                expression=connection_string,
                ref_id=ref_id,
            )

            for property_name, property_value in connection["property_expressions"].items():
                self.add_metadata_row(
                    asset_type="connection",
                    object_type="connection_property_expression",
                    object_name=property_name,
                    operation="property_expression",
                    connection_name=name,
                    expression=property_value,
                    ref_id=ref_id,
                )

        return connections

    def parse_configurations(self) -> list[dict[str, Any]]:
        collection = self.first_child(self.root, "Configurations")
        elements = self.children(collection, "Configuration") if collection is not None else []
        configurations = []

        for element in elements:
            configuration = {
                "name": self.attr(element, "ObjectName") or self.attr(element, "ConfigurationString"),
                "ref_id": self.attr(element, "refId"),
                "configuration_type": self.attr(element, "ConfigurationType"),
                "configuration_string": self.attr(element, "ConfigurationString"),
                "configured_type": self.attr(element, "ConfiguredType"),
                "package_path": self.attr(element, "PackagePath"),
                "value_type": self.attr(element, "ValueType"),
            }
            configurations.append(configuration)
            self.add_metadata_row(
                asset_type="configuration",
                object_type="package_configuration",
                object_name=configuration["name"],
                operation="configure",
                expression=configuration["configuration_string"],
                ref_id=configuration["ref_id"],
            )

        return configurations

    def parse_variables(self) -> list[dict[str, Any]]:
        variables = []

        for element in self.descendants(self.root, "Variable"):
            name = self.attr(element, "ObjectName") or self.name_from_ref(self.attr(element, "refId"))
            namespace = self.attr(element, "Namespace")
            value_element = self.first_child(element, "VariableValue")
            variable = {
                "name": name,
                "qualified_name": f"{namespace}::{name}" if namespace else name,
                "namespace": namespace,
                "data_type": self.attr(value_element, "DataType") if value_element is not None else "",
                "value": self.text(value_element) if value_element is not None else "",
                "ref_id": self.attr(element, "refId"),
                "expression": self.attr(element, "Expression"),
                "read_only": self.attr(element, "ReadOnly"),
            }
            variables.append(variable)
            self.add_metadata_row(
                asset_type="variable",
                object_type="ssis_variable",
                object_name=variable["qualified_name"],
                operation="define_variable",
                data_type=variable["data_type"],
                expression=variable["expression"] or variable["value"],
                ref_id=variable["ref_id"],
            )

        return variables

    def parse_executables(self) -> list[dict[str, Any]]:
        executables = []

        for element in self.descendants(self.root, "Executable"):
            name = self.attr(element, "ObjectName") or self.name_from_ref(self.attr(element, "refId"))
            ref_id = self.attr(element, "refId")
            executable_type = self.attr(element, "ExecutableType")
            creation_name = self.attr(element, "CreationName")
            executable = {
                "name": name,
                "ref_id": ref_id,
                "creation_name": creation_name,
                "executable_type": executable_type,
                "description": self.attr(element, "Description"),
                "parent_ref_id": self.attr(self.parent_map.get(element), "refId") if self.parent_map.get(element) is not None else "",
                "task_kind": self.task_kind(element),
                "path_depth": ref_id.count("\\") if ref_id else 0,
            }
            executables.append(executable)
            self.add_metadata_row(
                asset_type="control_flow",
                object_type="executable",
                object_name=name,
                operation=executable["task_kind"],
                task_name=name,
                expression=creation_name,
                ref_id=ref_id,
            )

        return executables

    def parse_sql_tasks(self) -> list[dict[str, Any]]:
        tasks = []

        for sql_element in self.descendants(self.root, "SqlTaskData"):
            executable = self.nearest_executable(sql_element)
            task_name = self.attr(executable, "ObjectName") if executable is not None else "SQL Task"
            ref_id = self.attr(executable, "refId") if executable is not None else ""
            connection_ref = self.attr(sql_element, "Connection", namespace=SQL_TASK_NAMESPACE)
            connection = self.connections_by_dtsid.get(connection_ref, {})
            sql = self.attr(sql_element, "SqlStatementSource", namespace=SQL_TASK_NAMESPACE)
            parsed_sql = parse_sql_objects(sql)
            task = {
                "task_name": task_name,
                "ref_id": ref_id,
                "connection_ref": connection_ref,
                "connection_name": connection.get("name", ""),
                "server_name": connection.get("server_name", ""),
                "database_name": connection.get("database_name", ""),
                "operation": parsed_sql.operation,
                "targets": parsed_sql.targets,
                "sources": parsed_sql.sources,
                "insert_columns": parsed_sql.insert_columns,
                "sql_statement": sql,
            }
            tasks.append(task)

            self.add_metadata_row(
                asset_type="sql_task",
                object_type="sql_statement",
                object_name=task_name,
                operation=parsed_sql.operation,
                task_name=task_name,
                connection_name=task["connection_name"],
                server_name=task["server_name"],
                database_name=task["database_name"],
                sql_excerpt=sql_excerpt(sql),
                ref_id=ref_id,
            )

            for target in parsed_sql.targets:
                object_parts = split_table_name(target)
                self.add_metadata_row(
                    asset_type="sql_task",
                    object_type="target_table",
                    object_name=target,
                    operation=parsed_sql.operation,
                    task_name=task_name,
                    connection_name=task["connection_name"],
                    server_name=task["server_name"],
                    database_name=object_parts.get("database_name") or task["database_name"],
                    schema_name=object_parts.get("schema_name", ""),
                    table_name=object_parts.get("table_name", ""),
                    target_object=target,
                    sql_excerpt=sql_excerpt(sql),
                    ref_id=ref_id,
                )

            for source in parsed_sql.sources:
                object_parts = split_table_name(source)
                self.add_metadata_row(
                    asset_type="sql_task",
                    object_type="source_table",
                    object_name=source,
                    operation="read",
                    task_name=task_name,
                    connection_name=task["connection_name"],
                    server_name=task["server_name"],
                    database_name=object_parts.get("database_name") or task["database_name"],
                    schema_name=object_parts.get("schema_name", ""),
                    table_name=object_parts.get("table_name", ""),
                    source_object=source,
                    sql_excerpt=sql_excerpt(sql),
                    ref_id=ref_id,
                )

            for column in parsed_sql.insert_columns:
                self.add_metadata_row(
                    asset_type="sql_task",
                    object_type="target_column",
                    object_name=column,
                    operation=parsed_sql.operation,
                    task_name=task_name,
                    connection_name=task["connection_name"],
                    column_name=column,
                    target_object=parsed_sql.targets[0] if parsed_sql.targets else "",
                    ref_id=ref_id,
                )

            for source in parsed_sql.sources:
                for target in parsed_sql.targets:
                    self.add_lineage_edge(
                        source=source,
                        target=target,
                        relationship_type="sql_object_lineage",
                        task_name=task_name,
                        source_object=source,
                        target_object=target,
                        operation=parsed_sql.operation,
                        expression=sql_excerpt(sql, 320),
                        confidence="medium",
                        ref_id=ref_id,
                    )

        return tasks

    def parse_data_flows(self) -> list[dict[str, Any]]:
        data_flows = []

        for pipeline in self.descendants(self.root, "pipeline"):
            executable = self.nearest_executable(pipeline)
            task_name = self.attr(executable, "ObjectName") if executable is not None else "Data Flow"
            ref_id = self.attr(executable, "refId") if executable is not None else ""
            components = self.parse_pipeline_components(pipeline, task_name, ref_id)
            paths = self.parse_pipeline_paths(pipeline, task_name, ref_id)
            column_mappings = self.parse_pipeline_column_mappings(pipeline, task_name, ref_id)
            data_flows.append(
                {
                    "task_name": task_name,
                    "ref_id": ref_id,
                    "components": components,
                    "paths": paths,
                    "column_mappings": column_mappings,
                }
            )

        return data_flows

    def parse_pipeline_components(self, pipeline: ET.Element, task_name: str, task_ref_id: str) -> list[dict[str, Any]]:
        components = []

        components_collection = self.first_child(pipeline, "components")
        for element in self.children(components_collection, "component") if components_collection is not None else []:
            properties = self.parse_pipeline_properties(element)
            connection = self.parse_pipeline_connection(element)
            component_ref_id = self.attr(element, "refId")
            component_name = self.attr(element, "name") or self.name_from_ref(component_ref_id)
            component_class = self.attr(element, "componentClassID")
            openrowset = properties.get("OpenRowset", "")
            sql_command = properties.get("SqlCommand", "")
            object_name = normalize_table_reference(openrowset) or first_table_from_sql(sql_command)
            role = component_role(component_class, component_name)
            connection_info = self.connections_by_ref.get(connection.get("connectionManagerRefId", ""), {})
            object_parts = split_table_name(object_name)
            component = {
                "name": component_name,
                "ref_id": component_ref_id,
                "component_class": component_class,
                "description": self.attr(element, "description"),
                "role": role,
                "connection_name": connection_info.get("name", connection.get("connectionManagerRefId", "")),
                "connection_ref_id": connection.get("connectionManagerRefId", ""),
                "server_name": connection_info.get("server_name", ""),
                "database_name": object_parts.get("database_name") or connection_info.get("database_name", ""),
                "schema_name": object_parts.get("schema_name", ""),
                "table_name": object_parts.get("table_name", ""),
                "object_name": object_name,
                "properties": properties,
                "connections": connection,
            }
            components.append(component)
            self.component_index[component_ref_id] = component

            self.add_metadata_row(
                asset_type="data_flow",
                object_type=f"{role}_component",
                object_name=object_name or component_name,
                operation=role,
                task_name=task_name,
                component_name=component_name,
                component_class=component_class,
                connection_name=component["connection_name"],
                server_name=component["server_name"],
                database_name=component["database_name"],
                schema_name=component["schema_name"],
                table_name=component["table_name"],
                source_object=object_name if role == "source" else "",
                target_object=object_name if role == "destination" else "",
                expression=sql_excerpt(sql_command, 320),
                ref_id=component_ref_id,
            )

            for property_name, property_value in properties.items():
                if property_value:
                    self.add_metadata_row(
                        asset_type="data_flow",
                        object_type="component_property",
                        object_name=property_name,
                        operation="property",
                        task_name=task_name,
                        component_name=component_name,
                        component_class=component_class,
                        connection_name=component["connection_name"],
                        expression=property_value,
                        ref_id=component_ref_id,
                    )

            self.parse_component_columns(element, component, task_name)

        return components

    def parse_pipeline_paths(self, pipeline: ET.Element, task_name: str, task_ref_id: str) -> list[dict[str, Any]]:
        paths = []
        paths_collection = self.first_child(pipeline, "paths")

        for element in self.children(paths_collection, "path") if paths_collection is not None else []:
            source_component_ref = component_ref_from_endpoint(self.attr(element, "startId"))
            target_component_ref = component_ref_from_endpoint(self.attr(element, "endId"))
            source_component = self.component_index.get(source_component_ref, {})
            target_component = self.component_index.get(target_component_ref, {})
            source_name = source_component.get("object_name") or source_component.get("name") or source_component_ref
            target_name = target_component.get("object_name") or target_component.get("name") or target_component_ref
            path_info = {
                "name": self.attr(element, "name"),
                "ref_id": self.attr(element, "refId"),
                "start_id": self.attr(element, "startId"),
                "end_id": self.attr(element, "endId"),
                "source_component": source_component.get("name", source_component_ref),
                "target_component": target_component.get("name", target_component_ref),
                "source_object": source_component.get("object_name", ""),
                "target_object": target_component.get("object_name", ""),
            }
            paths.append(path_info)

            self.add_metadata_row(
                asset_type="data_flow",
                object_type="data_flow_path",
                object_name=path_info["name"],
                operation="pipeline_path",
                task_name=task_name,
                source_object=path_info["source_object"],
                target_object=path_info["target_object"],
                expression=f"{path_info['source_component']} -> {path_info['target_component']}",
                ref_id=path_info["ref_id"],
            )

            self.add_lineage_edge(
                source=source_name,
                target=target_name,
                relationship_type="data_flow_path",
                task_name=task_name,
                component_name=path_info["name"],
                source_object=path_info["source_object"],
                target_object=path_info["target_object"],
                operation="data_flow",
                confidence="high",
                ref_id=path_info["ref_id"],
            )

        return paths

    def parse_pipeline_column_mappings(self, pipeline: ET.Element, task_name: str, task_ref_id: str) -> list[dict[str, Any]]:
        mappings = []

        for component_element in self.descendants(pipeline, "component"):
            component_ref_id = self.attr(component_element, "refId")
            component = self.component_index.get(component_ref_id, {})
            component_name = component.get("name", self.attr(component_element, "name"))
            target_object = component.get("object_name", "")
            role = component.get("role", "")

            for input_column in self.descendants(component_element, "inputColumn"):
                lineage_id = self.attr(input_column, "lineageId")
                source_column = self.output_column_index.get(lineage_id, {})
                source_object = source_column.get("object_name", "")
                target_column = self.attr(input_column, "cachedName") or self.name_from_ref(self.attr(input_column, "refId"))
                source_column_name = source_column.get("column_name", target_column)
                mapping = {
                    "task_name": task_name,
                    "component_name": component_name,
                    "component_role": role,
                    "source_object": source_object,
                    "target_object": target_object,
                    "source_column": source_column_name,
                    "target_column": target_column,
                    "data_type": self.attr(input_column, "cachedDataType"),
                    "lineage_id": lineage_id,
                    "ref_id": self.attr(input_column, "refId"),
                }
                mappings.append(mapping)

                if source_column_name or target_column:
                    self.add_metadata_row(
                        asset_type="column_lineage",
                        object_type="column_mapping",
                        object_name=f"{source_column_name} -> {target_column}",
                        operation="map_column",
                        task_name=task_name,
                        component_name=component_name,
                        source_object=source_object,
                        target_object=target_object,
                        column_name=target_column,
                        data_type=mapping["data_type"],
                        ref_id=mapping["ref_id"],
                    )

                if source_object or target_object:
                    self.add_lineage_edge(
                        source=f"{source_object}.{source_column_name}" if source_object and source_column_name else source_column_name,
                        target=f"{target_object}.{target_column}" if target_object and target_column else target_column,
                        relationship_type="column_mapping",
                        task_name=task_name,
                        component_name=component_name,
                        source_object=source_object,
                        target_object=target_object,
                        source_column=source_column_name,
                        target_column=target_column,
                        operation="map_column",
                        confidence="high",
                        ref_id=mapping["ref_id"],
                    )

        return mappings

    def parse_component_columns(self, component_element: ET.Element, component: dict[str, Any], task_name: str) -> None:
        object_name = component.get("object_name", "")
        component_name = component.get("name", "")
        component_class = component.get("component_class", "")
        role = component.get("role", "")

        for column in self.descendants(component_element, "outputColumn"):
            ref_id = self.attr(column, "refId")
            column_name = self.attr(column, "name") or self.name_from_ref(ref_id)
            column_info = {
                "ref_id": ref_id,
                "column_name": column_name,
                "data_type": self.attr(column, "dataType"),
                "object_name": object_name,
                "component_name": component_name,
                "component_class": component_class,
            }
            self.output_column_index[ref_id] = column_info
            self.add_metadata_row(
                asset_type="data_flow_column",
                object_type="output_column",
                object_name=column_name,
                operation=f"{role}_output",
                task_name=task_name,
                component_name=component_name,
                component_class=component_class,
                source_object=object_name if role == "source" else "",
                target_object=object_name if role == "destination" else "",
                column_name=column_name,
                data_type=column_info["data_type"],
                ref_id=ref_id,
            )

        for column in self.descendants(component_element, "externalMetadataColumn"):
            ref_id = self.attr(column, "refId")
            column_name = self.attr(column, "name") or self.name_from_ref(ref_id)
            self.add_metadata_row(
                asset_type="data_flow_column",
                object_type="external_metadata_column",
                object_name=column_name,
                operation=f"{role}_metadata",
                task_name=task_name,
                component_name=component_name,
                component_class=component_class,
                source_object=object_name if role == "source" else "",
                target_object=object_name if role == "destination" else "",
                column_name=column_name,
                data_type=self.attr(column, "dataType"),
                ref_id=ref_id,
            )

    def parse_precedence_constraints(self) -> list[dict[str, Any]]:
        constraints = []

        for element in self.descendants(self.root, "PrecedenceConstraint"):
            constraint = {
                "name": self.attr(element, "ObjectName") or self.name_from_ref(self.attr(element, "refId")),
                "ref_id": self.attr(element, "refId"),
                "from": self.attr(element, "From"),
                "to": self.attr(element, "To"),
                "logical_and": self.attr(element, "LogicalAnd"),
                "eval_op": self.attr(element, "EvalOp"),
                "value": self.attr(element, "Value"),
                "expression": self.attr(element, "Expression"),
            }
            constraints.append(constraint)

            self.add_metadata_row(
                asset_type="control_flow",
                object_type="precedence_constraint",
                object_name=constraint["name"],
                operation="control_flow_dependency",
                source_object=constraint["from"],
                target_object=constraint["to"],
                expression=constraint["expression"] or constraint["value"],
                ref_id=constraint["ref_id"],
            )

            self.add_lineage_edge(
                source=constraint["from"],
                target=constraint["to"],
                relationship_type="precedence_constraint",
                operation="control_flow",
                expression=constraint["expression"] or constraint["value"],
                confidence="high",
                ref_id=constraint["ref_id"],
            )

        return constraints

    def parse_event_handlers(self) -> list[dict[str, Any]]:
        handlers = []

        for element in self.descendants(self.root, "EventHandler"):
            handler = {
                "name": self.attr(element, "EventID") or self.name_from_ref(self.attr(element, "refId")),
                "ref_id": self.attr(element, "refId"),
                "creation_name": self.attr(element, "CreationName"),
                "executable_type": self.attr(element, "ExecutableType"),
            }
            handlers.append(handler)
            self.add_metadata_row(
                asset_type="event_handler",
                object_type="event_handler",
                object_name=handler["name"],
                operation="handle_event",
                expression=handler["creation_name"],
                ref_id=handler["ref_id"],
            )

        return handlers

    def parse_pipeline_properties(self, element: ET.Element) -> dict[str, str]:
        properties = {}
        properties_element = self.first_child(element, "properties")
        for property_element in self.children(properties_element, "property") if properties_element is not None else []:
            name = self.attr(property_element, "name")
            if name:
                properties[name] = self.text(property_element)
        return properties

    def parse_pipeline_connection(self, element: ET.Element) -> dict[str, str]:
        connections_element = self.first_child(element, "connections")
        connection_element = self.first_child(connections_element, "connection") if connections_element is not None else None
        if connection_element is None:
            return {}
        return {
            "name": self.attr(connection_element, "name"),
            "refId": self.attr(connection_element, "refId"),
            "connectionManagerID": self.attr(connection_element, "connectionManagerID"),
            "connectionManagerRefId": self.attr(connection_element, "connectionManagerRefId"),
        }

    def parse_property_expressions(self, element: ET.Element) -> dict[str, str]:
        expressions = {}
        for expression in self.children(element, "PropertyExpression"):
            name = self.attr(expression, "Name")
            if name:
                expressions[name] = self.text(expression)
        return expressions

    def task_kind(self, executable: ET.Element) -> str:
        executable_type = self.attr(executable, "ExecutableType")
        creation_name = self.attr(executable, "CreationName")
        if "Pipeline" in executable_type or "Pipeline" in creation_name:
            return "data_flow_task"
        if "ExecuteSQLTask" in executable_type or "ExecuteSQLTask" in creation_name:
            return "execute_sql_task"
        if "Sequence" in executable_type or "Sequence" in creation_name:
            return "sequence_container"
        if executable is self.root:
            return "package"
        return "task"

    def add_metadata_row(self, **values: Any) -> None:
        row = {column: "" for column in STANDARD_COLUMNS}
        row["package_name"] = self.package_name
        row["scope"] = values.pop("scope", self.package_name)
        for key, value in values.items():
            if key in row:
                row[key] = safe_string(value)
        self.metadata_rows.append(row)

    def add_lineage_edge(self, **values: Any) -> None:
        row = {column: "" for column in LINEAGE_COLUMNS}
        for key, value in values.items():
            if key in row:
                row[key] = safe_string(value)
        if row["source"] and row["target"] and row["source"] != row["target"]:
            self.lineage_edges.append(row)

    def normalize_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        normalized = []
        for row in rows:
            clean = {column: safe_string(row.get(column, "")) for column in STANDARD_COLUMNS}
            key = tuple(clean[column] for column in STANDARD_COLUMNS)
            if key not in seen:
                seen.add(key)
                normalized.append(clean)
        return normalized

    def normalize_edges(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        normalized = []
        for row in rows:
            clean = {column: safe_string(row.get(column, "")) for column in LINEAGE_COLUMNS}
            key = tuple(clean[column] for column in LINEAGE_COLUMNS)
            if key not in seen:
                seen.add(key)
                normalized.append(clean)
        return normalized

    def nearest_executable(self, element: ET.Element | None) -> ET.Element | None:
        current = element
        while current is not None:
            if self.local_name(current.tag) == "Executable":
                return current
            current = self.parent_map.get(current)
        return None

    def first_child(self, element: ET.Element | None, name: str) -> ET.Element | None:
        if element is None:
            return None
        for child in list(element):
            if self.local_name(child.tag) == name:
                return child
        return None

    def children(self, element: ET.Element | None, name: str) -> list[ET.Element]:
        if element is None:
            return []
        return [child for child in list(element) if self.local_name(child.tag) == name]

    def descendants(self, element: ET.Element | None, name: str) -> list[ET.Element]:
        if element is None:
            return []
        return [node for node in element.iter() if self.local_name(node.tag) == name]

    def first_descendant(self, element: ET.Element | None, name: str, exclude_self: bool = False) -> ET.Element | None:
        if element is None:
            return None
        for node in element.iter():
            if exclude_self and node is element:
                continue
            if self.local_name(node.tag) == name:
                return node
        return None

    def attr(self, element: ET.Element | None, name: str, namespace: str | None = None) -> str:
        if element is None:
            return ""
        namespace_candidates = [namespace] if namespace else [DTS_NAMESPACE, SQL_TASK_NAMESPACE, ""]
        for candidate in namespace_candidates:
            key = f"{{{candidate}}}{name}" if candidate else name
            value = element.attrib.get(key)
            if value is not None:
                return value
        return ""

    def text(self, element: ET.Element | None) -> str:
        if element is None or element.text is None:
            return ""
        return str(element.text).strip()

    def local_name(self, tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if tag.startswith("{") else tag

    def name_from_ref(self, ref_id: str) -> str:
        if not ref_id:
            return ""
        matches = re.findall(r"\[([^\]]+)\]", ref_id)
        if matches:
            return matches[-1]
        return ref_id.split("\\")[-1].split(".")[-1]


def parse_connection_string(connection_string: str) -> dict[str, str]:
    parsed = {}
    for part in connection_string.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        parsed[key.strip().lower()] = value.strip()
    return parsed


def parse_sql_objects(sql: str) -> SqlObjects:
    normalized = normalize_sql(sql)
    operation = detect_operation(normalized)
    targets = unique_preserve_order(extract_target_tables(normalized))
    sources = unique_preserve_order(extract_source_tables(normalized))
    insert_columns = extract_insert_columns(normalized)
    sources = [source for source in sources if source not in targets]
    return SqlObjects(operation=operation, targets=targets, sources=sources, insert_columns=insert_columns)


def detect_operation(sql: str) -> str:
    first_word = re.search(r"\b(INSERT|MERGE|UPDATE|DELETE|TRUNCATE|SELECT|EXEC|EXECUTE)\b", sql, flags=re.IGNORECASE)
    if not first_word:
        return "sql"
    value = first_word.group(1).lower()
    return "execute" if value in {"exec", "execute"} else value


def extract_target_tables(sql: str) -> list[str]:
    patterns = [
        r"\bINSERT\s+INTO\s+([#@\[\]\"`\w\.\-]+)",
        r"\bMERGE\s+(?:INTO\s+)?([#@\[\]\"`\w\.\-]+)",
        r"\bUPDATE\s+([#@\[\]\"`\w\.\-]+)",
        r"\bDELETE\s+FROM\s+([#@\[\]\"`\w\.\-]+)",
        r"\bTRUNCATE\s+TABLE\s+([#@\[\]\"`\w\.\-]+)",
        r"\bSELECT\b.+?\bINTO\s+([#@\[\]\"`\w\.\-]+)",
    ]
    targets = []
    for pattern in patterns:
        for match in re.finditer(pattern, sql, flags=re.IGNORECASE | re.DOTALL):
            target = normalize_table_reference(match.group(1))
            if is_valid_table_reference(target):
                targets.append(target)
    return targets


def extract_source_tables(sql: str) -> list[str]:
    sources = []
    pattern = r"\b(?:FROM|JOIN|USING|APPLY)\s+([#@\[\]\"`\w\.\-]+)"
    for match in re.finditer(pattern, sql, flags=re.IGNORECASE):
        source = normalize_table_reference(match.group(1))
        if is_valid_table_reference(source):
            sources.append(source)
    return sources


def extract_insert_columns(sql: str) -> list[str]:
    match = re.search(r"\bINSERT\s+INTO\s+[#@\[\]\"`\w\.\-]+\s*\((.*?)\)\s*(?:SELECT|VALUES)", sql, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return []
    columns = []
    for raw_column in split_csv_sql(match.group(1)):
        column = normalize_identifier(raw_column)
        if column:
            columns.append(column)
    return columns


def first_table_from_sql(sql: str) -> str:
    parsed = parse_sql_objects(sql)
    if parsed.sources:
        return parsed.sources[0]
    if parsed.targets:
        return parsed.targets[0]
    return ""


def normalize_sql(sql: str) -> str:
    without_block_comments = re.sub(r"/\*.*?\*/", " ", sql or "", flags=re.DOTALL)
    without_line_comments = re.sub(r"--[^\n\r]*", " ", without_block_comments)
    return re.sub(r"\s+", " ", without_line_comments).strip()


def normalize_table_reference(value: str) -> str:
    if not value:
        return ""
    cleaned = value.strip().rstrip(",;")
    cleaned = cleaned.strip("()")
    if cleaned.upper() in {"SELECT", "VALUES", "ON", "WITH"}:
        return ""
    cleaned = cleaned.replace('"', "").replace("`", "")
    parts = [normalize_identifier(part) for part in cleaned.split(".") if normalize_identifier(part)]
    return ".".join(parts)


def normalize_identifier(value: str) -> str:
    cleaned = str(value or "").strip().strip(",;")
    cleaned = cleaned.strip("[]")
    cleaned = cleaned.replace("[", "").replace("]", "")
    cleaned = cleaned.strip('"').strip("`")
    return cleaned.strip()


def is_valid_table_reference(value: str) -> bool:
    if not value:
        return False
    upper = value.upper()
    invalid = {
        "SELECT",
        "VALUES",
        "SET",
        "ON",
        "WHERE",
        "GROUP",
        "ORDER",
        "BY",
        "BEGIN",
        "END",
    }
    if upper in invalid:
        return False
    if value.startswith("@"):
        return False
    return bool(re.search(r"[A-Za-z0-9_#]", value))


def split_csv_sql(value: str) -> list[str]:
    parts = []
    current = []
    depth = 0
    for char in value:
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return parts


def split_table_name(object_name: str) -> dict[str, str]:
    parts = [part for part in object_name.split(".") if part]
    if len(parts) >= 3:
        return {"database_name": parts[-3], "schema_name": parts[-2], "table_name": parts[-1]}
    if len(parts) == 2:
        return {"database_name": "", "schema_name": parts[-2], "table_name": parts[-1]}
    if len(parts) == 1:
        return {"database_name": "", "schema_name": "", "table_name": parts[-1]}
    return {"database_name": "", "schema_name": "", "table_name": ""}


def component_role(component_class: str, component_name: str) -> str:
    value = f"{component_class} {component_name}".lower()
    if "source" in value:
        return "source"
    if "destination" in value:
        return "destination"
    if "lookup" in value:
        return "lookup"
    if "merge" in value:
        return "merge"
    if "conditional" in value:
        return "conditional_split"
    if "multicast" in value:
        return "multicast"
    if "derived" in value:
        return "derived_column"
    return "transform"


def component_ref_from_endpoint(endpoint: str) -> str:
    if not endpoint:
        return ""
    for marker in [".Outputs[", ".Inputs["]:
        if marker in endpoint:
            return endpoint.split(marker, 1)[0]
    return endpoint


def sql_excerpt(sql: str, length: int = 180) -> str:
    value = normalize_sql(sql)
    if len(value) <= length:
        return value
    return f"{value[:length].rstrip()}..."


def unique_preserve_order(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def safe_string(value: Any) -> str:
    if value is None:
        return ""
    return str(value)
