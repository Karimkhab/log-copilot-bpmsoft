# Пояснительная записка: LogCopilot

## 1. Ссылка на репозиторий исходных кодов

Репозиторий проекта: [https://github.com/Karimkhab/log-copilot-bpmsoft](https://github.com/Karimkhab/log-copilot-bpmsoft)

## 2. Цель и задача проекта

Цель проекта LogCopilot - упростить первичный анализ логов BPMSoft и смежных серверных логов, чтобы быстрее находить инциденты, пики нагрузки, проблемы трафика и качество самих входных данных.

Задачи решения:

- принять один `.log` файл или пакетно обработать директорию с `.log` файлами;
- автоматически выбрать подходящий парсер или применить fallback-разбор;
- привести разные форматы логов к единой структуре событий;
- сохранить события, агрегаты и результаты запусков в SQLite;
- сформировать файловые артефакты для пользователя и интеграций: JSON, CSV, Markdown, JSONL;
- поддержать три режима анализа: `heatmap`, `incidents`, `traffic`;
- опционально сформировать интерпретацию через Yandex LLM, при этом сохранять работоспособность без внешней модели.

## 3. Технологии и инструменты

| Компонент | Название и версия | Назначение |
| --- | --- | --- |
| Язык | Python >= 3.9, Docker/CI: Python 3.11, локальная проверка: Python 3.12.0 | Основной runtime проекта |
| Пакет проекта | logcopilot 0.1.0 | CLI и библиотечный пакет |
| Сборка Python-пакета | setuptools >= 68 | Установка проекта и CLI-команды `logcopilot` |
| Контейнеризация | Docker, базовый образ `python:3.11-slim` | Серверный запуск без ручной настройки окружения |
| Оркестрация контейнера | Docker Compose file format для `docker compose` | Удобный batch-запуск с volume для логов и результатов |
| Хранилище | SQLite через стандартный модуль `sqlite3` | Сохранение запусков, событий и агрегатов |
| Табличная обработка | pandas 3.0.2 | Работа с табличными данными и совместимость артефактов |
| Parquet | pyarrow 23.0.1 | Опциональная запись событий в Parquet |
| Прогресс | tqdm 4.67.3 | Индикация долгих операций |
| Семантические эмбеддинги | sentence-transformers 5.4.1 | Векторизация сигнатур инцидентов |
| ML-кластеризация | scikit-learn 1.8.0, hdbscan 0.8.42, umap-learn 0.5.12 | Семантическая группировка похожих ошибок |
| Визуализация | matplotlib 3.10.8 | Подготовка графиков и серверный non-GUI backend `Agg` |
| LLM-интеграции | langchain 1.2.15, langchain-openai 1.1.14, langgraph 1.1.8 | Задел под агентные сценарии; текущий Yandex-вызов реализован через HTTP |
| Внешняя LLM | YandexGPT, модель по умолчанию `yandexgpt` | Опциональная интерпретация результатов |

Примечание: `requirements.txt` содержит прямые зависимости без жесткой фиксации версий. Версии в таблице отражают проверенную локальную среду на 20.05.2026; Docker-образ устанавливает зависимости из `requirements.txt`.

## 4. Архитектурный подход

В проекте используется конвейерная архитектура с явными этапами обработки:

`CLI -> parsing -> event building -> storage -> profile computation -> artifacts -> agent interpretation -> quality validation -> final output`.

Ключевые подходы:

- staged pipeline: каждый этап принимает и возвращает общий `PipelineContext`;
- strategy/registry для выбора парсеров логов;
- profile strategy для режимов `heatmap`, `incidents`, `traffic`;
- repository-подход для SQLite-хранилища;
- dataclass-контракты для конфигурации, результатов этапов, карточек находок и итоговой сводки;
- deterministic fallback: если LLM не включена или не настроена, решение все равно строит полезные карточки и отчеты.

## 5. Стартовые допущения и ограничения

- Один запуск `run` принимает ровно один `.log` файл.
- Пакетный режим `batch` обходит директорию и запускает отдельный анализ для каждого `.log` файла.
- Вход читается как UTF-8 с заменой некорректных символов.
- События текущего запуска хранятся в памяти до записи агрегатов; для очень больших логов потребуется потоковая доработка.
- Семантическая кластеризация требует зависимости `sentence-transformers`, `scikit-learn` и может скачать модель `sentence-transformers/all-MiniLM-L6-v2`.
- Внешний LLM-этап опционален и требует `YC_FOLDER_ID`, `YC_AI_API_KEY`, `YC_MODEL`.
- Секреты не хранятся в репозитории; пример переменных лежит в `.env.example`.
- Docker-контейнер ожидает, что логи будут смонтированы в `/app/data`, а результаты - в `/app/out`.

## 6. Алгоритмические решения

### Парсинг

Сначала система ищет `.log` файлы, затем для каждого файла выбирает парсер. Для известных BPMSoft-имен файлов применяются подсказки: `Request.log`, `Error.log`, `BusinessProcess.log`, `AspNetCore.log`. Для остальных форматов работает реестр парсеров с оценкой уверенности: JSON, logfmt, BPMSoft request, web access, Windows servicing, syslog, text multiline. Если уверенность ниже порога, используется `GenericFallbackParser`.

### Нормализация и события

Канонические события превращаются в доменную модель `Event`. Сообщения нормализуются: маскируются переменные части вроде чисел, UUID, IP и токенов, затем строится `signature_hash`. Это позволяет группировать повторяющиеся ошибки без привязки к конкретным ID и адресам.

### Хранение

Для каждого запуска создается `run_id`, директория `out/runs/<run_id>` и запись в `out/logcopilot.sqlite`. События пишутся батчами по 1000 записей. Агрегаты профилей сохраняются в отдельные таблицы SQLite.

### Heatmap

Профиль строит поминутные бакеты по времени, компоненту и операции. Для каждого бакета считаются `hits`, `qps`, `p95_latency_ms`. Дополнительно выделяются горячие интервалы, активные компоненты, операции, HTTP-статусы и всплески активности IP.

### Incidents

Профиль группирует события по сигнатурам сообщений и признакам инцидента. Для кластеров считаются количество попаданий, первые и последние появления, уровни логирования, stacktrace и confidence. Семантический слой группирует похожие сигнатуры через эмбеддинги и HDBSCAN; если HDBSCAN недоступен, предусмотрен DBSCAN.

### Traffic

Профиль агрегирует события по `method`, `path`, `http_status`, считает частоту, уникальные IP, `p95` и `p99` задержки, средний размер ответа. Аномалии выделяются по 5xx-ответам, высокой задержке и scan-like активности IP.

### Качество и fit профиля

Слой качества оценивает покрытие timestamp, level, stacktrace, долю fallback-парсинга, среднюю уверенность парсера и сигнал инцидентности. Отдельно считается соответствие выбранного профиля входному логу и рекомендация более подходящего профиля.

### Agent stage

Агентский этап получает компактные факты по запуску, профилю и качеству. Если Yandex LLM настроен, выполняется внешний вызов. Если провайдер выключен или параметры отсутствуют, используется детерминированная интерпретация на основе рассчитанных фактов.

### Итоговые артефакты

Финальный этап записывает `run_summary.json`, `findings.json`, `siem_findings.jsonl`, `zabbix_metrics.json` и профильные отчеты. Форматы выбраны так, чтобы результат можно было читать вручную и подключать к внешним системам мониторинга.

## 7. Модули проекта

| Путь | Назначение |
| --- | --- |
| `src/cli.py` | CLI-команды `run` и `batch` |
| `src/pipeline.py` | Главная оркестрация этапов конвейера |
| `src/domain/` | Dataclass-контракты конфигурации, событий, результатов и карточек |
| `src/parsing/` | Реестр парсеров, обнаружение файлов, канонические модели логов |
| `src/parsing/parsers/` | Конкретные парсеры JSON, logfmt, syslog, web access, BPMSoft, Windows и fallback |
| `src/core/` | Построение доменных событий из канонических записей |
| `src/text/` | Нормализация сообщений и построение сигнатур |
| `src/profiles/` | Реализация профилей `heatmap`, `incidents`, `traffic` |
| `src/analysis/` | Метрики качества, fit профиля, кластеризация |
| `src/storage/` | SQLite-репозиторий и этапы записи |
| `src/output/` | Запись JSON, CSV, Markdown, JSONL и финальной сводки |
| `src/agent/` | Подготовка фактов, промптов, Yandex-конфигурации и fallback-интерпретации |
| `tests/` | Unit- и integration-тесты |
| `data/` | Примеры логов для локальной проверки |
| `Dockerfile` | Сборка production-like CLI-образа |
| `docker-compose.yml` | Удобный запуск контейнера с volume для `data`, `out` и кэша моделей |

## 8. Как собрать решение

Локальная сборка:

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
```

Сборка Docker-образа:

```bash
docker build -t logcopilot:latest .
```

Сборка через Docker Compose:

```bash
docker compose build
```

Проверка тестов:

```bash
python -m unittest discover -s tests
```

## 9. Как задеплоить или развернуть решение

Вариант для сервера через Docker:

1. Установить Docker и Docker Compose plugin.
2. Склонировать репозиторий.
3. Собрать образ командой `docker build -t logcopilot:latest .`.
4. Подготовить директории с логами и результатами, например `data/` и `out/`.
5. При необходимости задать переменные Yandex Cloud: `YC_FOLDER_ID`, `YC_AI_API_KEY`, `YC_MODEL`.
6. Запускать анализ через `docker run` или `docker compose run`.

Пример серверного запуска:

```bash
docker run --rm \
  -v "$PWD/data:/app/data:ro" \
  -v "$PWD/out:/app/out" \
  logcopilot:latest \
  batch --input /app/data --profile auto --out /app/out --semantic off
```

Если используется семантический режим, рекомендуется смонтировать persistent-кэш:

```bash
docker run --rm \
  -v "$PWD/data:/app/data:ro" \
  -v "$PWD/out:/app/out" \
  -v logcopilot-cache:/app/.cache \
  logcopilot:latest \
  batch --input /app/data --profile auto --out /app/out --semantic on
```

## 10. Как запустить решение

Локальный запуск одного файла:

```bash
python -m src.cli run --input data/nginx_logs.log --profile traffic --out out --semantic off
```

Локальный batch-запуск:

```bash
python -m src.cli batch --input data --profile auto --out out --semantic off
```

Docker-запуск одного файла:

```bash
docker run --rm \
  -v "$PWD/data:/app/data:ro" \
  -v "$PWD/out:/app/out" \
  logcopilot:latest \
  run --input /app/data/nginx_logs.log --profile traffic --out /app/out --semantic off
```

Docker Compose batch-запуск:

```bash
docker compose run --rm logcopilot batch --input /app/data --profile auto --out /app/out --semantic off
```

На Linux-сервере рекомендуется передавать UID/GID текущего пользователя, чтобы результаты в `out` создавались не от root:

```bash
LOGCOPILOT_UID="$(id -u)" LOGCOPILOT_GID="$(id -g)" \
  docker compose run --rm logcopilot batch --input /app/data --profile auto --out /app/out --semantic off
```

Запуск с Yandex LLM:

```bash
docker run --rm \
  -e YC_FOLDER_ID="$YC_FOLDER_ID" \
  -e YC_AI_API_KEY="$YC_AI_API_KEY" \
  -e YC_MODEL="${YC_MODEL:-yandexgpt}" \
  -v "$PWD/data:/app/data:ro" \
  -v "$PWD/out:/app/out" \
  logcopilot:latest \
  run --input /app/data/apache_logs.log --profile incidents --out /app/out --agent-provider yandex --semantic off
```

## 11. Руководство пользователя

Основная команда:

```bash
logcopilot run --input <file.log> --profile <heatmap|incidents|traffic> --out <out_dir>
```

Пакетная команда:

```bash
logcopilot batch --input <logs_dir> --profile auto --out <out_dir>
```

Режимы работы:

- `heatmap` - анализ нагрузки по минутам, компонентам и операциям. Используется для поиска пиков, горячих точек и всплесков активности.
- `incidents` - анализ ошибок, сигнатур, stacktrace и похожих инцидентов. Используется для поиска повторяющихся проблем и top-кластеров.
- `traffic` - анализ HTTP-трафика, статусов, endpoint-ов, задержек и подозрительной активности IP.
- `batch --profile auto` - автоматический выбор профиля для известных имен BPMSoft-логов; для неизвестных файлов по умолчанию используется `heatmap`.

Полезные флаги:

- `--semantic off` - быстрый запуск без загрузки embedding-модели.
- `--semantic on` - включить семантическую группировку инцидентов.
- `--semantic-model` - указать модель sentence-transformers.
- `--clean-out` - очистить директорию конкретного запуска перед записью.
- `--agent-provider yandex` - включить внешний LLM-провайдер.
- `--agent-question` - передать фокусирующий вопрос для агентского этапа.

После запуска результаты появляются в `out/runs/<run_id>/`, а общая SQLite-база - в `out/logcopilot.sqlite`.

## 12. ToDo

- Зафиксировать production-версии зависимостей отдельным lock/constraints-файлом.
- Добавить потоковую обработку очень больших логов без хранения всех событий в памяти.
- Расширить набор BPMSoft-специфичных парсеров и автоопределение профиля.
- Добавить Docker CI-проверку сборки образа.
- Сделать web/API-интерфейс поверх CLI для регулярного серверного анализа.
- Добавить планировщик периодического анализа директорий с логами.
- Улучшить отчеты графиками для heatmap и traffic.
- Добавить больше интеграционных тестов на реальные наборы BPMSoft-логов.
- Добавить экспорт в Prometheus/OpenTelemetry наряду с SIEM JSONL и Zabbix JSON.
