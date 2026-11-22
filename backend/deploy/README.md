# Сборка и запуск ЛР5

Команды из корня `lab5_rsoi`. Нужны Go из `backend/go.mod`, Docker + Compose,
buildx, Helm, kubectl, jq, openssl; для облака — AWS CLI. IdP пока не выбран.

## Текущее состояние

Перенесена реализация ЛР4 без изменения Go-кода и SQL. Авторизация ещё старая:
`X-User-Name`; JWT из задания ЛР5 пока не реализован. Корневой README,
OpenAPI и Postman-коллекции ЛР5 сохранены. Облачный стенд не создан.

## Проверки и локальный запуск

~~~bash
bash scripts/check.sh
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
Параметры будущего кластера и IdP уточняются отдельно; команды ниже их не создают.

~~~bash
export KUBE_CONTEXT=rsoi-lab5-aws
export KUBE_NAMESPACE=library-system
kubectl --context "$KUBE_CONTEXT" create namespace "$KUBE_NAMESPACE"
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

## CI и тесты задания

`classroom.yml` пока запускает только `scripts/check.sh`, без push образов,
деплоя и ложного зачёта OAuth-тестов. Автопроверка настроена на `v4`, но требует
реализованной авторизации, работающего IdP и заполненного окружения.
Специфический cloud/failover runner ЛР4 не используется с новой коллекцией ЛР5.

ARC-конфиги перенесены для следующего этапа: репозиторий `Nok1o/lab5_rsoi`,
scale set `lab5-cloud-runner`, образ `nok1o/lab5_rsoi:ci-runner-v1`.
Существующий `runner.sh deploy` требует предварительной настройки ARC Secret
и namespace; сейчас его выполнять не нужно.
