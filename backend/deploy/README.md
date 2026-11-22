# Сборка и запуск ЛР5

Команды из корня `lab5_rsoi`. Нужны Go из `backend/go.mod`, Docker + Compose,
buildx, Helm, kubectl, jq, openssl; для облака — AWS CLI. IdP — Auth0, подпись RS256.

## Текущее состояние

Перенесена реализация ЛР4. Добавлены OIDC-конфиги и `backend/shared/auth`:
discovery, кеш JWKS, проверка RS256, issuer, audience, exp, nbf, sub.
Также готово HTTP middleware: Bearer → verifier → Principal в request context,
проверка scopes, ответы 401/403. **Middleware пока не подключено к маршрутам:
API ещё не защищено JWT, используется `X-User-Name`.** Подключение к сервисам,
проброс токенов и получение worker-токена — следующие шаги.
Корневой README, OpenAPI и Postman-коллекции ЛР5 сохранены. Облачный стенд не создан.

## Проверки и локальный запуск

~~~bash
bash scripts/check.sh
cp .env.example .env
# Заполнить .env значениями своего Auth0 tenant и M2M-приложения worker.
docker compose up --build -d
docker compose ps
curl --fail http://localhost:8080/manage/health
curl --fail --get --data-urlencode 'city=Москва' \
  --data 'page=1&size=10' http://localhost:8080/api/v1/libraries
docker compose down
~~~

`check.sh`: build, unit-тесты с race detector, vet, синтаксис Bash и Helm.
Первый запуск требует скачивания Go-зависимостей и официальных ARC charts.
Если `docker compose` недоступен, использовать установленный `docker-compose`
с теми же аргументами.
PostgreSQL integration-тесты пропускаются без `RATING_TEST_DATABASE_URL` и
`RESERVATION_TEST_DATABASE_URL`. Docker volumes сохраняются при `compose down`.

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
Health/authorize/callback нужно регистрировать вне защищённого router, без
исключений по строковому префиксу. Токены из context не сохранять в Redis и не логировать.

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

`classroom.yml` пока запускает только `scripts/check.sh`, без push образов,
деплоя и ложного зачёта OAuth-тестов. Автопроверка настроена на `v4`, но требует
реализованной авторизации, работающего IdP и заполненного окружения.
Специфический cloud/failover runner ЛР4 не используется с новой коллекцией ЛР5.

ARC-конфиги перенесены для следующего этапа: репозиторий `Nok1o/lab5_rsoi`,
scale set `lab5-cloud-runner`, образ `nok1o/lab5_rsoi:ci-runner-v1`.
Существующий `runner.sh deploy` требует предварительной настройки ARC Secret
и namespace; сейчас его выполнять не нужно.
