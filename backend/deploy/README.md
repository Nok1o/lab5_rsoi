# Сборка и запуск ЛР5

Команды из корня `lab5_rsoi`. Нужны Go из `backend/go.mod`, Node.js 24 + npm,
Docker + Compose, buildx, Helm, kubectl, jq, openssl; для облака — AWS CLI.
IdP — Auth0, подпись RS256.

## Текущее состояние

Перенесена реализация ЛР4. Добавлены OIDC-конфиги и `backend/shared/auth`:
discovery, кеш JWKS, проверка RS256, issuer, audience, exp, nbf, sub.
HTTP middleware подключено ко всем API-маршрутам четырёх сервисов:
Bearer → verifier → Principal в request context, проверка scopes, ответы 401/403.
Пользователь определяется по `sub`, `X-User-Name` игнорируется. Gateway передаёт
пользовательский JWT синхронным HTTP-клиентам. Worker использует отдельный
Client Credentials token для внутренних операций; JWT в Redis не сохраняется.
Публичным остаётся `/manage/health`. `/api/v1/authorize` и `/api/v1/callback`
пока не реализованы; пользовательский access token получать напрямую в Auth0.
Корневой README и OpenAPI сохранены. В Postman адаптирован Auth0-запрос токена
и параметризованы даты; все 14 запросов и проверки сохранены. Облачный стенд не создан.

## Проверки и локальный запуск

~~~bash
bash scripts/check.sh
npm ci --prefix scripts --ignore-scripts --no-audit --no-fund
npm test --prefix scripts
cp .env.example .env
# Заполнить .env: tenant, M2M worker, пользовательское приложение и тестовый пользователь.
set -a
source .env
set +a
docker compose up --build -d
docker compose ps
curl --fail http://localhost:8080/manage/health
# ACCESS_TOKEN — заранее полученный пользовательский access token Auth0.
curl --fail --get --data-urlencode 'city=Москва' \
  --header "Authorization: Bearer $ACCESS_TOKEN" \
  --data 'page=1&size=10' http://localhost:8080/api/v1/libraries
bash scripts/test-script.sh v4
docker compose down
~~~

`check.sh`: build, unit-тесты с race detector, vet, синтаксис Bash и Helm.
Первый запуск требует скачивания Go-зависимостей и официальных ARC charts.
Если `docker compose` недоступен, использовать установленный `docker-compose`
с теми же аргументами.
PostgreSQL integration-тесты пропускаются без `RATING_TEST_DATABASE_URL` и
`RESERVATION_TEST_DATABASE_URL`. Docker volumes сохраняются при `compose down`.
Redis integration-тесты требуют `REDIS_TEST_URL`. Для curl установить локально
`ACCESS_TOKEN` в пользовательский access token Auth0; без него API возвращает 401.
Newman получает токен сам через Password grant, используя `AUTH0_TEST_CLIENT_ID`,
`AUTH0_TEST_CLIENT_SECRET`, `AUTH0_TEST_USERNAME`, `AUTH0_TEST_PASSWORD` из shell.
Пароли/JWT не передаются в CLI-аргументах и не экспортируются в отчёты; итог —
только очищенный `test-reports/newman.xml`. Прогон изменяет тестовые данные.
Для Postman импортировать `v4/postman/{collection,environment}.json`, заполнить
окружение: `identityProviderUrl` без завершающего `/`, `audience`, `clientId`,
`clientSecret`, `username`, `password`. Не экспортировать заполненные secrets в Git.
Запускать всю коллекцию через Runner: JWT хранится только в local run scope,
а не в экспортируемых collection variables.

`OIDC_ISSUER` — точный issuer Auth0 с завершающим `/`; две audience — Identifier
пользовательского и внутреннего API, не Client ID. Worker Client ID/Secret
передаются только Gateway. Для `go run` экспортировать те же переменные в shell.
Без обязательных OIDC-параметров конфиг сервиса возвращает ошибку; режима bypass нет.
`.env` не коммитить и не публиковать вывод `docker compose config` с секретами.

Verifier выбирает одну ожидаемую audience на вызов, не объединяет две.
При создании загружает discovery/JWKS по HTTPS, принимает только ключи с того же
хоста. Ключи кешируются на 5 минут, неизвестный `kid` вызывает обновление не чаще
раза в 30 секунд; до следующей попытки новый ключ может временно отклоняться.
При недоступности IdP свежие ключи работают, просроченный кеш не используется.
Тесты используют локальный HTTPS IdP, а не реальный Auth0.
`NewMiddleware(verifier, audience)` задаёт одну audience; `Authenticate` читает
только `Authorization: Bearer`, сохраняет проверенные Principal и access token
в request context. `RequireScopes(...)` после него требует все указанные scopes.
Отсутствующие/некорректные credentials дают 401 с `WWW-Authenticate: Bearer`,
недостаточные scopes — 403, недоступность IdP при обновлении ключей — 503.
Health зарегистрирован вне защищённого router. Токены из context не сохранять
в Redis и не логировать. Авторизация и HTTP redirects не используются как fallback.

Worker получает `/oauth/token` из OIDC discovery, запрашивает
`client_credentials` для `OIDC_INTERNAL_AUDIENCE` со scope `returns:complete`,
проверяет подпись, audience, scope и собственные `sub`/Client ID. Токен хранится
в памяти и обновляется до истечения, параллельные worker используют общий кеш.
При 401 он сбрасывается для следующей попытки, изменяющий запрос автоматически
не повторяется. Ошибка получения токена оставляет доставку pending.
Внутренние маршруты требуют внутреннюю audience, M2M-идентичность
(`sub == client_id + "@clients"` для Auth0) и scope `returns:complete`:

- Library: GET `/internal/v1/libraries/{libraryUid}/books/{bookUid}`,
  POST тот же путь с `/return`.
- Rating: PATCH `/internal/v1/rating`, JSON `{"username":"<sub пользователя>","delta":1}`.

Worker не может брать книги, отменять резервации или вызывать пользовательское API.
Gateway не публикует внутренние маршруты через свой Ingress. В Auth0 внутренний
API должен разрешать только M2M worker, без user-delegated access; выдать worker
scope `returns:complete`. После принятого возврата истечение пользовательского
JWT между этапами не мешает передать оставшуюся работу worker.

## Образы

~~~bash
export DOCKERHUB_NAMESPACE=nok1o
export DOCKERHUB_REPOSITORY=lab5_rsoi
export IMAGE_TAG="manual-$(date -u +%Y%m%d%H%M%S)"
docker login --username "$DOCKERHUB_NAMESPACE"
bash backend/deploy/images.sh plan
bash backend/deploy/images.sh build
bash backend/deploy/images.sh push
~~~

Публикация требует доступа к выбранному Docker Hub repository.
Образы: `<namespace>/lab5_rsoi:<library|rating|reservation|gateway>-$IMAGE_TAG`,
платформа `linux/amd64`. Для одного сервиса добавить его имя последним аргументом.

## Helm: после создания кластера

Сначала установить EBS CSI/StorageClass `gp3` и Traefik (`IngressClass: traefik`).
Параметры будущего кластера уточняются отдельно; команды ниже его не создают.

~~~bash
export KUBE_CONTEXT=rsoi-lab5-aws
export KUBE_NAMESPACE=library-system
kubectl --context "$KUBE_CONTEXT" create namespace "$KUBE_NAMESPACE"
# .env — доверенный локальный файл; не включать shell tracing (set -x).
set -a
source .env
set +a
kubectl --context "$KUBE_CONTEXT" -n "$KUBE_NAMESPACE" create configmap oidc-config \
  --from-literal=OIDC_ISSUER="$OIDC_ISSUER" \
  --from-literal=OIDC_AUDIENCE="$OIDC_AUDIENCE" \
  --from-literal=OIDC_INTERNAL_AUDIENCE="$OIDC_INTERNAL_AUDIENCE"
printf 'OIDC_WORKER_CLIENT_ID=%s\nOIDC_WORKER_CLIENT_SECRET=%s\n' \
  "$OIDC_WORKER_CLIENT_ID" "$OIDC_WORKER_CLIENT_SECRET" | \
  kubectl --context "$KUBE_CONTEXT" -n "$KUBE_NAMESPACE" create secret generic \
    oidc-worker-credentials --from-env-file=/dev/stdin
kubectl --context "$KUBE_CONTEXT" -n "$KUBE_NAMESPACE" create secret generic postgresql-credentials \
  --from-literal=POSTGRES_PASSWORD="$(openssl rand -hex 24)" \
  --from-literal=LIBRARIES_DB_PASSWORD="$(openssl rand -hex 24)" \
  --from-literal=RESERVATIONS_DB_PASSWORD="$(openssl rand -hex 24)" \
  --from-literal=RATINGS_DB_PASSWORD="$(openssl rand -hex 24)"
kubectl --context "$KUBE_CONTEXT" -n "$KUBE_NAMESPACE" create secret generic redis-credentials \
  --from-literal=REDIS_PASSWORD="$(openssl rand -hex 24)"
bash backend/deploy/infrastructure.sh deploy
bash backend/deploy/application.sh deploy
~~~

Для существующих Secrets пароли не генерировать заново. SQL применяется к пустому
PGDATA. PVC/EBS с `Retain` сохраняются и оплачиваются после удаления ресурсов.
`oidc-config` читают все четыре сервиса; `oidc-worker-credentials` — только Gateway.
После изменения OIDC ConfigMap/Secret перезапустить соответствующие Deployments:
значения окружения уже запущенных контейнеров автоматически не обновляются.

## CI и тесты задания

`classroom.yml`: build/unit/Helm и тесты Newman runner для PR/push; реальная
Auth0-интеграция — только доверенный `master` (push или workflow_dispatch).
GitHub-hosted runner поднимает отдельный Compose project со свежими volumes,
ждёт health всех сервисов, запускает 14 запросов через Classroom grader (10 баллов),
публикует очищенный JUnit и удаляет только ресурсы своего прогона. Нет push образов
или облачного деплоя. Отсутствующие параметры приводят к явной ошибке, не к пропуску.

В GitHub → Settings → Secrets and variables → Actions задать:

- Variables: `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_INTERNAL_AUDIENCE`,
  `OIDC_WORKER_CLIENT_ID`, `AUTH0_TEST_CLIENT_ID`.
- Secrets: `OIDC_WORKER_CLIENT_SECRET`, `AUTH0_TEST_CLIENT_SECRET`,
  `AUTH0_TEST_USERNAME`, `AUTH0_TEST_PASSWORD`.

Использовать отдельного Auth0-пользователя для тестов. Коллекция проверяет Password
grant и синхронные пользовательские API; она не упражняет deferred worker с реальным
Auth0. Локальные unit/integration-тесты worker используют HTTPS IdP stand-in.
Google Sheet marker без преподавательского токена не подключён.

ARC-конфиги перенесены для следующего этапа: репозиторий `Nok1o/lab5_rsoi`,
scale set `lab5-cloud-runner`, образ `nok1o/lab5_rsoi:ci-runner-v1`.
Существующий `runner.sh deploy` требует предварительной настройки ARC Secret
и namespace; сейчас его выполнять не нужно.
