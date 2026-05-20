from __future__ import annotations

"""SQLite-репозиторий для запусков конвейера, артефактов и агрегатов профилей."""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional

from ..domain import ClusterSummary, Event, SemanticClusterSummary
from ..output.reporting import format_timestamp

logger = logging.getLogger(__name__)


def utc_now() -> str:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        Нет параметров.
    
    Returns:
        str: Текущее время UTC в ISO-формате с суффиксом `Z` без микросекунд.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class StorageRepository:
    """SQLite-репозиторий для запусков конвейера, артефактов и агрегатов профилей."""

    def __init__(self, db_path: Path) -> None:
        """Инициализирует объект и сохраняет параметры, необходимые для дальнейшей работы.

        Args:
            db_path (Path): Путь к SQLite-базе данных, где хранятся результаты запусков.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def connect(self) -> sqlite3.Connection:
        """Выполняет вспомогательную операцию для логики проекта.
        
        Args:
            Нет параметров.
        
        Returns:
            sqlite3.Connection: Открытое SQLite-соединение с row_factory=sqlite3.Row для доступа к колонкам по имени.
        """
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_schema(self) -> None:
        """Выполняет вспомогательную операцию для логики проекта.

        Args:
            Нет параметров.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    input_path TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    output_dir TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    event_count INTEGER DEFAULT 0,
                    summary_json TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    parser_profile TEXT NOT NULL,
                    parser_confidence REAL NOT NULL DEFAULT 0,
                    timestamp TEXT,
                    level TEXT,
                    component TEXT,
                    message TEXT NOT NULL,
                    stacktrace TEXT NOT NULL,
                    raw_text TEXT NOT NULL,
                    line_count INTEGER NOT NULL,
                    normalized_message TEXT NOT NULL,
                    signature_hash TEXT NOT NULL,
                    embedding_text TEXT NOT NULL,
                    exception_type TEXT,
                    stack_frames TEXT DEFAULT '',
                    request_id TEXT,
                    trace_id TEXT,
                    http_status INTEGER,
                    method TEXT,
                    path TEXT,
                    latency_ms REAL,
                    response_size INTEGER,
                    client_ip TEXT,
                    user_agent TEXT,
                    attributes_json TEXT DEFAULT '{}',
                    is_incident INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    artifact_name TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(run_id, artifact_name),
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS agent_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL DEFAULT '',
                    overall_status TEXT NOT NULL DEFAULT 'unknown',
                    confidence REAL NOT NULL DEFAULT 0,
                    short_summary TEXT NOT NULL DEFAULT '',
                    technical_summary TEXT NOT NULL DEFAULT '',
                    business_summary TEXT NOT NULL DEFAULT '',
                    question TEXT NOT NULL,
                    answer TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    facts_json TEXT NOT NULL,
                    key_findings_json TEXT NOT NULL DEFAULT '[]',
                    recommended_actions_json TEXT NOT NULL DEFAULT '[]',
                    limitations_json TEXT NOT NULL DEFAULT '[]',
                    cards_json TEXT NOT NULL DEFAULT '[]',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    input_context_json TEXT NOT NULL DEFAULT '{}',
                    trace_json TEXT NOT NULL,
                    visuals_json TEXT NOT NULL,
                    artifact_paths_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(run_id),
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS agent_cards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    card_index INTEGER NOT NULL,
                    card_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL,
                    UNIQUE(run_id, card_index),
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS incident_clusters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    cluster_id TEXT NOT NULL,
                    hits INTEGER NOT NULL,
                    incident_hits INTEGER NOT NULL,
                    confidence_score REAL NOT NULL,
                    confidence_label TEXT NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT,
                    representative_text TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    UNIQUE(run_id, cluster_id),
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS semantic_clusters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    semantic_cluster_id INTEGER NOT NULL,
                    signature_hash TEXT NOT NULL,
                    hits INTEGER NOT NULL,
                    representative_text TEXT NOT NULL,
                    avg_cosine_similarity REAL NOT NULL,
                    member_signature_hashes TEXT NOT NULL,
                    UNIQUE(run_id, semantic_cluster_id),
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS heatmap_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    bucket_start TEXT NOT NULL,
                    component TEXT,
                    operation TEXT,
                    hits INTEGER NOT NULL,
                    qps REAL NOT NULL,
                    p95_latency_ms REAL,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS traffic_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    method TEXT,
                    path TEXT,
                    http_status INTEGER,
                    hits INTEGER NOT NULL,
                    unique_ips INTEGER NOT NULL,
                    p95_latency_ms REAL,
                    p99_latency_ms REAL,
                    avg_response_size REAL,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS traffic_anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                );
                """
            )
            self._ensure_column(connection, "events", "parser_confidence", "REAL NOT NULL DEFAULT 0")
            self._ensure_column(connection, "events", "attributes_json", "TEXT DEFAULT '{}'")
            self._ensure_column(connection, "agent_results", "model", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "agent_results", "overall_status", "TEXT NOT NULL DEFAULT 'unknown'")
            self._ensure_column(connection, "agent_results", "confidence", "REAL NOT NULL DEFAULT 0")
            self._ensure_column(connection, "agent_results", "short_summary", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "agent_results", "technical_summary", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "agent_results", "business_summary", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "agent_results", "key_findings_json", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(connection, "agent_results", "recommended_actions_json", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(connection, "agent_results", "limitations_json", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(connection, "agent_results", "cards_json", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(connection, "agent_results", "result_json", "TEXT NOT NULL DEFAULT '{}'")
            self._ensure_column(connection, "agent_results", "input_context_json", "TEXT NOT NULL DEFAULT '{}'")

    def _ensure_column(self, connection: sqlite3.Connection, table_name: str, column_name: str, ddl: str) -> None:
        """Проверяет или подготавливает внутренний ресурс, необходимый для выполнения этапа.

        Args:
            connection (sqlite3.Connection): Открытое соединение с базой данных, через которое выполняются SQL-операции.
            table_name (str): Имя переменной, поля, провайдера или ресурса, значение которого обрабатывается.
            column_name (str): Имя переменной, поля, провайдера или ресурса, значение которого обрабатывается.
            ddl (str): Значение `ddl`, используемое функцией при выполнении операции.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        columns = {
            row["name"]
            for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column_name not in columns:
            connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl}")

    def _decode_json_payload_rows(
        self,
        rows: Iterable[sqlite3.Row],
        column_name: str = "payload_json",
    ) -> List[dict]:
        """Выполняет вспомогательную операцию для JSON, полезной нагрузки, строк.
        
        Args:
            rows (Iterable[sqlite3.Row]): Строки табличных данных, которые нужно записать, агрегировать или проверить.
            column_name (str, optional): Имя переменной, поля, провайдера или ресурса, значение которого обрабатывается.
        
        Returns:
            List[dict]: Список строк БД, где JSON-поле payload декодировано и объединено с остальными колонками.
        """
        payload = []
        for row in rows:
            item = dict(row)
            item[column_name] = json.loads(item[column_name] or "{}")
            payload.append(item)
        return payload

    def _decode_json_payload_row(
        self,
        row: Optional[sqlite3.Row],
        column_name: str = "payload_json",
    ) -> Optional[dict]:
        """Выполняет вспомогательную операцию для JSON, полезной нагрузки, строки.
        
        Args:
            row (Optional[sqlite3.Row]): Одна строка табличных данных, из которой строится объект результата.
            column_name (str, optional): Имя переменной, поля, провайдера или ресурса, значение которого обрабатывается.
        
        Returns:
            Optional[dict]: Одна строка БД с декодированным JSON payload или None, если строка отсутствует.
        """
        if row is None:
            return None
        item = dict(row)
        item[column_name] = json.loads(item[column_name] or "{}")
        return item

    def _dict_rows(self, rows: Iterable[sqlite3.Row]) -> List[dict]:
        """Выполняет вспомогательную операцию для строк.
        
        Args:
            rows (Iterable[sqlite3.Row]): Строки табличных данных, которые нужно записать, агрегировать или проверить.
        
        Returns:
            List[dict]: Список sqlite3.Row, преобразованных в обычные словари.
        """
        return [dict(row) for row in rows]

    def _fetchall(self, query: str, params: Iterable[object] = ()) -> List[sqlite3.Row]:
        """Выполняет вспомогательную операцию для логики проекта.
        
        Args:
            query (str): SQL-запрос, который нужно выполнить к базе данных.
            params (Iterable[object], optional): Параметры SQL-запроса, подставляемые безопасным способом.
        
        Returns:
            List[sqlite3.Row]: Все строки результата SQL-запроса.
        """
        with self.connect() as connection:
            return connection.execute(query, tuple(params)).fetchall()

    def _fetchone(self, query: str, params: Iterable[object] = ()) -> Optional[sqlite3.Row]:
        """Выполняет вспомогательную операцию для логики проекта.
        
        Args:
            query (str): SQL-запрос, который нужно выполнить к базе данных.
            params (Iterable[object], optional): Параметры SQL-запроса, подставляемые безопасным способом.
        
        Returns:
            Optional[sqlite3.Row]: Первая строка результата SQL-запроса или None, если данных нет.
        """
        with self.connect() as connection:
            return connection.execute(query, tuple(params)).fetchone()

    def _executemany(self, query: str, rows: List[tuple[object, ...]]) -> None:
        """Выполняет вспомогательную операцию для логики проекта.

        Args:
            query (str): SQL-запрос, который нужно выполнить к базе данных.
            rows (List[tuple[object, ...]]): Строки табличных данных, которые нужно записать, агрегировать или проверить.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        if not rows:
            return
        with self.connect() as connection:
            connection.executemany(query, rows)

    def create_run(self, run_id: str, input_path: str, profile: str, output_dir: str) -> None:
        """Создает новую запись, объект или ресурс, необходимый для выполнения конвейера.

        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            input_path (str): Путь к входному файлу или директории с логами.
            profile (str): Профиль анализа логов, определяющий набор вычислений и формат результата.
            output_dir (str): Директория, в которой создаются артефакты текущего запуска.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO runs (run_id, input_path, profile, output_dir, created_at, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (run_id, input_path, profile, output_dir, utc_now(), "running"),
            )
        logger.info(
            "storage_create_run: run_id=%s profile=%s output_dir=%s",
            run_id,
            profile,
            output_dir,
        )

    def complete_run(self, run_id: str, status: str, event_count: int, summary: dict) -> None:
        """Завершает ранее созданную запись запуска с итоговым статусом и сводкой.

        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            status (str): Значение `status`, используемое функцией при выполнении операции.
            event_count (int): Значение `event_count`, используемое функцией при выполнении операции.
            summary (dict): Сводная структура с метриками, статусами и диагностикой выполнения.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE runs
                SET status = ?, completed_at = ?, event_count = ?, summary_json = ?
                WHERE run_id = ?
                """,
                (status, utc_now(), event_count, json.dumps(summary, indent=2), run_id),
            )
        logger.info(
            "storage_complete_run: run_id=%s status=%s event_count=%d",
            run_id,
            status,
            event_count,
        )

    def insert_events(self, events: Iterable[Event]) -> None:
        """Добавляет набор данных в постоянное хранилище проекта. Область применения: событий.

        Args:
            events (Iterable[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        rows = [
            (
                event.event_id,
                event.run_id,
                event.source_file,
                event.parser_profile,
                event.parser_confidence,
                format_timestamp(event.timestamp),
                event.level,
                event.component,
                event.message,
                event.stacktrace,
                event.raw_text,
                event.line_count,
                event.normalized_message,
                event.signature_hash,
                event.embedding_text,
                event.exception_type,
                " | ".join(event.stack_frames),
                event.request_id,
                event.trace_id,
                event.http_status,
                event.method,
                event.path,
                event.latency_ms,
                event.response_size,
                event.client_ip,
                event.user_agent,
                json.dumps(event.attributes, ensure_ascii=False, sort_keys=True),
                int(event.is_incident),
            )
            for event in events
        ]
        self._executemany(
            """
            INSERT INTO events (
                event_id, run_id, source_file, parser_profile, parser_confidence, timestamp, level, component,
                message, stacktrace, raw_text, line_count, normalized_message, signature_hash,
                embedding_text, exception_type, stack_frames, request_id, trace_id, http_status,
                method, path, latency_ms, response_size, client_ip, user_agent, attributes_json, is_incident
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        logger.debug("storage_insert_events: rows=%d", len(rows))

    def register_artifact(self, run_id: str, artifact_name: str, artifact_type: str, path: str) -> None:
        """Регистрирует объект или артефакт в реестре, чтобы его могли использовать следующие этапы. Область применения: артефакта.

        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            artifact_name (str): Имя артефакта в манифесте и базе данных.
            artifact_type (str): Тип артефакта, используемый при регистрации результата.
            path (str): Путь к файлу или артефакту, с которым работает функция.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO artifacts (run_id, artifact_name, artifact_type, path, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(run_id, artifact_name)
                DO UPDATE SET artifact_type = excluded.artifact_type, path = excluded.path
                """,
                (run_id, artifact_name, artifact_type, path, utc_now()),
            )
        logger.info(
            "storage_register_artifact: run_id=%s artifact=%s type=%s path=%s",
            run_id,
            artifact_name,
            artifact_type,
            path,
        )

    def store_agent_result(self, run_id: str, result: dict, input_context: Optional[dict] = None) -> None:
        """Сохраняет данные текущего этапа в постоянное хранилище. Область применения: агентского этапа.

        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            result (dict): Результат выполнения конвейера или промежуточного этапа, из которого берутся данные.
            input_context (Optional[dict], optional): Структурированный контекст для агентского этапа с фактами, диагностикой и сводками.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO agent_results (
                    run_id, status, provider, model, overall_status, confidence,
                    short_summary, technical_summary, business_summary, question, answer, profile,
                    plan_json, facts_json, key_findings_json, recommended_actions_json,
                    limitations_json, cards_json, result_json, input_context_json,
                    trace_json, visuals_json, artifact_paths_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id)
                DO UPDATE SET
                    status = excluded.status,
                    provider = excluded.provider,
                    model = excluded.model,
                    overall_status = excluded.overall_status,
                    confidence = excluded.confidence,
                    short_summary = excluded.short_summary,
                    technical_summary = excluded.technical_summary,
                    business_summary = excluded.business_summary,
                    question = excluded.question,
                    answer = excluded.answer,
                    profile = excluded.profile,
                    plan_json = excluded.plan_json,
                    facts_json = excluded.facts_json,
                    key_findings_json = excluded.key_findings_json,
                    recommended_actions_json = excluded.recommended_actions_json,
                    limitations_json = excluded.limitations_json,
                    cards_json = excluded.cards_json,
                    result_json = excluded.result_json,
                    input_context_json = excluded.input_context_json,
                    trace_json = excluded.trace_json,
                    visuals_json = excluded.visuals_json,
                    artifact_paths_json = excluded.artifact_paths_json,
                    created_at = excluded.created_at
                """,
                (
                    run_id,
                    result.get("status", "completed"),
                    result.get("provider", "none"),
                    result.get("model", ""),
                    result.get("overall_status", "unknown"),
                    result.get("confidence", 0.0),
                    result.get("short_summary", ""),
                    result.get("technical_summary", ""),
                    result.get("business_summary", ""),
                    "",
                    result.get("short_summary", ""),
                    result.get("profile", ""),
                    json.dumps({}, ensure_ascii=False, default=str),
                    json.dumps(input_context or {}, ensure_ascii=False, default=str),
                    json.dumps(result.get("key_findings", []), ensure_ascii=False, default=str),
                    json.dumps(result.get("recommended_actions", []), ensure_ascii=False, default=str),
                    json.dumps(result.get("limitations", []), ensure_ascii=False, default=str),
                    json.dumps(result.get("cards", []), ensure_ascii=False, default=str),
                    json.dumps(result, ensure_ascii=False, default=str),
                    json.dumps(input_context or {}, ensure_ascii=False, default=str),
                    json.dumps([], ensure_ascii=False, default=str),
                    json.dumps(result.get("cards", []), ensure_ascii=False, default=str),
                    json.dumps(result.get("artifact_paths", {}), ensure_ascii=False, default=str),
                    utc_now(),
                ),
            )
            connection.execute("DELETE FROM agent_cards WHERE run_id = ?", (run_id,))
            connection.executemany(
                """
                INSERT INTO agent_cards (
                    run_id, card_index, card_type, title, severity, confidence, payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        index,
                        card.get("card_type", ""),
                        card.get("title", ""),
                        card.get("severity", ""),
                        card.get("confidence", 0.0),
                        json.dumps(card, ensure_ascii=False, default=str),
                    )
                    for index, card in enumerate(result.get("cards", []))
                ],
            )
        logger.info(
            "storage_store_agent_result: run_id=%s status=%s provider=%s cards=%d",
            run_id,
            result.get("status", "completed"),
            result.get("provider", "none"),
            len(result.get("cards", [])),
        )

    def insert_incident_clusters(self, run_id: str, clusters: Iterable[ClusterSummary]) -> None:
        """Добавляет набор данных в постоянное хранилище проекта. Область применения: инцидента, кластеров.

        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            clusters (Iterable[ClusterSummary]): Список кластеров событий, используемый для отчетов или сохранения.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        rows = [
            (
                run_id,
                cluster.cluster_id,
                cluster.hits,
                cluster.incident_hits,
                cluster.confidence_score,
                cluster.confidence_label,
                format_timestamp(cluster.first_seen),
                format_timestamp(cluster.last_seen),
                cluster.representative_signature_text or cluster.representative_normalized,
                json.dumps(
                    {
                        "parser_profiles": cluster.parser_profiles,
                        "source_files": cluster.source_files,
                        "sample_messages": cluster.sample_messages.split(" || "),
                        "exception_type": cluster.example_exception,
                        "levels": cluster.levels,
                        "top_stack_frames": cluster.top_stack_frames,
                        "representative_raw": cluster.representative_raw,
                        "representative_normalized": cluster.representative_normalized,
                        "representative_signature_text": cluster.representative_signature_text,
                    }
                ),
            )
            for cluster in clusters
        ]
        self._executemany(
            """
            INSERT INTO incident_clusters (
                run_id, cluster_id, hits, incident_hits, confidence_score, confidence_label,
                first_seen, last_seen, representative_text, payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        logger.info("storage_insert_incident_clusters: run_id=%s rows=%d", run_id, len(rows))

    def insert_semantic_clusters(
        self,
        run_id: str,
        clusters: Iterable[SemanticClusterSummary],
    ) -> None:
        """Добавляет набор данных в постоянное хранилище проекта. Область применения: семантического анализа, кластеров.

        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            clusters (Iterable[SemanticClusterSummary]): Список кластеров событий, используемый для отчетов или сохранения.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        rows = [
            (
                run_id,
                cluster.semantic_cluster_id,
                cluster.signature_hash,
                cluster.hits,
                cluster.representative_text,
                cluster.avg_cosine_similarity,
                cluster.member_signature_hashes,
            )
            for cluster in clusters
        ]
        self._executemany(
            """
            INSERT INTO semantic_clusters (
                run_id, semantic_cluster_id, signature_hash, hits, representative_text,
                avg_cosine_similarity, member_signature_hashes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        logger.info("storage_insert_semantic_clusters: run_id=%s rows=%d", run_id, len(rows))

    def insert_heatmap_metrics(self, run_id: str, rows: Iterable[dict]) -> None:
        """Добавляет набор данных в постоянное хранилище проекта. Область применения: тепловой карты.

        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            rows (Iterable[dict]): Строки табличных данных, которые нужно записать, агрегировать или проверить.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        values = [
            (
                run_id,
                row["bucket_start"],
                row.get("component"),
                row.get("operation"),
                row["hits"],
                row["qps"],
                row.get("p95_latency_ms"),
            )
            for row in rows
        ]
        self._executemany(
            """
            INSERT INTO heatmap_metrics (
                run_id, bucket_start, component, operation, hits, qps, p95_latency_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        logger.info("storage_insert_heatmap_metrics: run_id=%s rows=%d", run_id, len(values))

    def insert_traffic_metrics(self, run_id: str, rows: Iterable[dict]) -> None:
        """Добавляет набор данных в постоянное хранилище проекта. Область применения: трафика.

        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            rows (Iterable[dict]): Строки табличных данных, которые нужно записать, агрегировать или проверить.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        values = [
            (
                run_id,
                row.get("method"),
                row.get("path"),
                row.get("http_status"),
                row["hits"],
                row["unique_ips"],
                row.get("p95_latency_ms"),
                row.get("p99_latency_ms"),
                row.get("avg_response_size"),
            )
            for row in rows
        ]
        self._executemany(
            """
            INSERT INTO traffic_metrics (
                run_id, method, path, http_status, hits, unique_ips, p95_latency_ms,
                p99_latency_ms, avg_response_size
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        logger.info("storage_insert_traffic_metrics: run_id=%s rows=%d", run_id, len(values))

    def insert_traffic_anomalies(self, run_id: str, rows: Iterable[dict]) -> None:
        """Добавляет набор данных в постоянное хранилище проекта. Область применения: трафика.

        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            rows (Iterable[dict]): Строки табличных данных, которые нужно записать, агрегировать или проверить.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        values = [
            (
                run_id,
                row["anomaly_type"],
                row["severity"],
                row["title"],
                row["details"],
                json.dumps(row.get("payload", {}), ensure_ascii=False),
            )
            for row in rows
        ]
        self._executemany(
            """
            INSERT INTO traffic_anomalies (
                run_id, anomaly_type, severity, title, details, payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        logger.info("storage_insert_traffic_anomalies: run_id=%s rows=%d", run_id, len(values))

    def list_runs(self, limit: int = 20) -> List[sqlite3.Row]:
        """Выполняет вспомогательную операцию для логики проекта.
        
        Args:
            limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
        
        Returns:
            List[sqlite3.Row]: Последние запуски конвейера, отсортированные от новых к старым.
        """
        return self._fetchall(
            """
            SELECT run_id, input_path, profile, output_dir, created_at, completed_at, status, event_count
            FROM runs
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        )

    def get_run_summary(self, run_id: str) -> Optional[dict]:
        """Возвращает данные из хранилища или подготовленной структуры по заданным условиям. Область применения: сводки.
        
        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
        
        Returns:
            Optional[dict]: Сводка запуска из runs.summary_json с добавленными служебными колонками; None, если run_id не найден.
        """
        run = self._fetchone("SELECT * FROM runs WHERE run_id = ?", (run_id,))
        if run is None:
            return None
        artifacts = self._fetchall(
            """
            SELECT artifact_name, artifact_type, path
            FROM artifacts
            WHERE run_id = ?
            ORDER BY artifact_name
            """,
            (run_id,),
        )
        summary = dict(run)
        summary["summary_json"] = json.loads(summary["summary_json"] or "{}")
        summary["artifacts"] = self._dict_rows(artifacts)
        return summary

    def get_artifact(self, run_id: str, artifact_name: str) -> Optional[dict]:
        """Возвращает данные из хранилища или подготовленной структуры по заданным условиям. Область применения: артефакта.
        
        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            artifact_name (str): Имя артефакта в манифесте и базе данных.
        
        Returns:
            Optional[dict]: Метаданные указанного артефакта запуска или None, если артефакт не зарегистрирован.
        """
        row = self._fetchone(
            """
            SELECT artifact_name, artifact_type, path
            FROM artifacts
            WHERE run_id = ? AND artifact_name = ?
            """,
            (run_id, artifact_name),
        )
        return dict(row) if row is not None else None

    def get_agent_result(self, run_id: str) -> Optional[dict]:
        """Возвращает данные из хранилища или подготовленной структуры по заданным условиям. Область применения: агентского этапа.
        
        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
        
        Returns:
            Optional[dict]: Сохраненный результат агентского этапа с декодированными JSON-полями или None.
        """
        row = self._fetchone(
            """
            SELECT status, provider, model, overall_status, confidence, short_summary,
                   technical_summary, business_summary, question, answer, profile,
                   plan_json, facts_json, key_findings_json, recommended_actions_json,
                   limitations_json, cards_json, result_json, input_context_json,
                   trace_json, visuals_json, artifact_paths_json, created_at
            FROM agent_results
            WHERE run_id = ?
            """,
            (run_id,),
        )
        if row is None:
            return None
        result = dict(row)
        for column_name in (
            "plan_json",
            "facts_json",
            "key_findings_json",
            "recommended_actions_json",
            "limitations_json",
            "cards_json",
            "result_json",
            "input_context_json",
            "trace_json",
            "visuals_json",
            "artifact_paths_json",
        ):
            result[column_name] = json.loads(result[column_name] or "{}")
        return result

    def get_agent_cards(self, run_id: str) -> List[dict]:
        """Возвращает данные из хранилища или подготовленной структуры по заданным условиям. Область применения: агентского этапа, карточек.
        
        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
        
        Returns:
            List[dict]: Карточки агентского результата для запуска, отсортированные по card_index.
        """
        rows = self._fetchall(
            """
            SELECT card_index, card_type, title, severity, confidence, payload_json
            FROM agent_cards
            WHERE run_id = ?
            ORDER BY card_index ASC
            """,
            (run_id,),
        )
        return self._decode_json_payload_rows(rows)

    def get_event_field_stats(self, run_id: str) -> dict:
        """Возвращает данные из хранилища или подготовленной структуры по заданным условиям. Область применения: события.
        
        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
        
        Returns:
            dict: Статистика заполненности ключевых полей событий для указанного запуска.
        """
        row = self._fetchone(
            """
            SELECT
                COUNT(*) AS total_events,
                SUM(CASE WHEN timestamp IS NOT NULL THEN 1 ELSE 0 END) AS timestamp_count,
                SUM(CASE WHEN level IS NOT NULL AND level != '' THEN 1 ELSE 0 END) AS level_count,
                SUM(CASE WHEN component IS NOT NULL AND component != '' THEN 1 ELSE 0 END) AS component_count,
                SUM(CASE WHEN method IS NOT NULL AND method != '' THEN 1 ELSE 0 END) AS method_count,
                SUM(CASE WHEN path IS NOT NULL AND path != '' THEN 1 ELSE 0 END) AS path_count,
                SUM(CASE WHEN http_status IS NOT NULL THEN 1 ELSE 0 END) AS http_status_count,
                SUM(CASE WHEN latency_ms IS NOT NULL THEN 1 ELSE 0 END) AS latency_count,
                SUM(CASE WHEN client_ip IS NOT NULL AND client_ip != '' THEN 1 ELSE 0 END) AS client_ip_count,
                AVG(parser_confidence) AS avg_parser_confidence
            FROM events
            WHERE run_id = ?
            """,
            (run_id,),
        )
        return dict(row) if row is not None else {}

    def get_top_incidents(self, run_id: str, limit: int = 10) -> List[dict]:
        """Возвращает данные из хранилища или подготовленной структуры по заданным условиям. Область применения: инцидентов.
        
        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
        
        Returns:
            List[dict]: Самые значимые incident-кластеры запуска с декодированной полезной нагрузкой.
        """
        rows = self._fetchall(
            """
            SELECT cluster_id, hits, incident_hits, confidence_score, confidence_label,
                   first_seen, last_seen, representative_text, payload_json
            FROM incident_clusters
            WHERE run_id = ?
            ORDER BY incident_hits DESC, hits DESC
            LIMIT ?
            """,
            (run_id, limit),
        )
        return self._decode_json_payload_rows(rows)

    def find_incident_cluster(self, run_id: str, cluster_id: str) -> Optional[dict]:
        """Выполняет вспомогательную операцию для инцидента, кластера.
        
        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            cluster_id (str): Значение `cluster_id`, используемое функцией при выполнении операции.
        
        Returns:
            Optional[dict]: Данные конкретного incident-кластера или None, если cluster_id не найден.
        """
        row = self._fetchone(
            """
            SELECT cluster_id, hits, incident_hits, confidence_score, confidence_label,
                   first_seen, last_seen, representative_text, payload_json
            FROM incident_clusters
            WHERE run_id = ? AND cluster_id = ?
            """,
            (run_id, cluster_id),
        )
        return self._decode_json_payload_row(row)

    def get_heatmap(self, run_id: str, limit: Optional[int] = 100) -> List[dict]:
        """Возвращает данные из хранилища или подготовленной структуры по заданным условиям. Область применения: тепловой карты.
        
        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            limit (Optional[int], optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
        
        Returns:
            List[dict]: Строки тепловой карты запуска, ограниченные limit и отсортированные по времени/нагрузке.
        """
        query = """
            SELECT bucket_start, component, operation, hits, qps, p95_latency_ms
            FROM heatmap_metrics
            WHERE run_id = ?
            ORDER BY hits DESC, bucket_start DESC
        """
        params: List[object] = [run_id]
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        rows = self._fetchall(query, params)
        return self._dict_rows(rows)

    def get_traffic_summary(
        self,
        run_id: str,
        status: Optional[int] = None,
        limit: int = 100,
    ) -> List[dict]:
        """Возвращает данные из хранилища или подготовленной структуры по заданным условиям. Область применения: трафика, сводки.
        
        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            status (Optional[int], optional): Значение `status`, используемое функцией при выполнении операции.
            limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
        
        Returns:
            List[dict]: Строки агрегатов трафика с методом, путем, статусом, количеством запросов и задержками.
        """
        query = """
            SELECT method, path, http_status, hits, unique_ips, p95_latency_ms, p99_latency_ms,
                   avg_response_size
            FROM traffic_metrics
            WHERE run_id = ?
        """
        params: List[object] = [run_id]
        if status is not None:
            query += " AND http_status = ?"
            params.append(status)
        query += " ORDER BY hits DESC, p95_latency_ms DESC LIMIT ?"
        params.append(limit)
        rows = self._fetchall(query, params)
        return self._dict_rows(rows)

    def get_traffic_anomalies(self, run_id: str, limit: int = 50) -> List[dict]:
        """Возвращает данные из хранилища или подготовленной структуры по заданным условиям. Область применения: трафика.
        
        Args:
            run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
            limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
        
        Returns:
            List[dict]: Сохраненные аномалии трафика для запуска, отсортированные по серьезности и лимиту.
        """
        rows = self._fetchall(
            """
            SELECT anomaly_type, severity, title, details, payload_json
            FROM traffic_anomalies
            WHERE run_id = ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (run_id, limit),
        )
        return self._decode_json_payload_rows(rows)
