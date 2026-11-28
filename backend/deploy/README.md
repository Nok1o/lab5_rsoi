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
и параметризованы даты; все 14 запросов и проверки сохранены. 27.11.2026 восстановлены
EKS `rsoi-lab5-aws`, ноды, ingress, PostgreSQL/Redis. Четыре Go-сервиса развёрнуты
из `nok1o/lab5_rsoi:<service>-cloud-5a57aa2-20261127`, public health возвращает 200.
NLB: `k8s-ingresss-traefik-ac3d411ed7-9fcc0f4de2166770.elb.us-east-2.amazonaws.com`.
27.11.2026 проверено с Mac через нативные WebSocket port-forward: Auth0-коллекция
14 запросов / 14 assertions / 0 failures; 8 проверок отказа credentials (401);
worker 8/8, Stream/pending пусты, все четыре Deployment восстановлены до 1/1.
Пользовательские client secret/пароль оставались локально. Очищенные отчёты:
`test-reports/cloud-local-websocket/{newman,worker-cloud}.xml` (не коммитить).

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
Пароли/JWT не передаются в CLI-аргументах и не экспортируются в отчёты. В логе —
полный стандартный CLI-отчёт Newman с запросами, проверками, console скриптов,
итоговой статистикой и подробной таблицей ошибок. Скрываются только значения credentials.
Артефакт — очищенный `test-reports/newman.xml`. Прогон изменяет тестовые данные.
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

## AWS: восстановление стенда

Аккаунт `076548329469`, регион `us-east-2`. Используем сохранённые VPC
`vpc-0fc0d510da47e906a`, публичные подсети `subnet-02e723053b5b32ea8` /
`subnet-0a3ce1cf7effbf20b` и IAM-роли `rsoi-lab4-*`. Новых NAT Gateway нет.
EKS и две EC2-ноды расходуют кредиты; Free Tier eligible не означает бесплатную EKS.
Перед созданием проверить баланс: `aws freetier get-account-plan-state`.

~~~bash
aws login
export AWS_REGION=us-east-2
export AWS_DEFAULT_REGION="$AWS_REGION"
export EKS_CLUSTER_NAME=rsoi-lab5-aws
export KUBE_CONTEXT=rsoi-lab5-aws
export KUBE_NAMESPACE=library-system
client_ipv4="$(curl -4 --fail --silent --show-error https://checkip.amazonaws.com)"
# Проверить, что client_ipv4 — текущий непустой IPv4 через рабочий VPN.
aws eks create-cluster --name "$EKS_CLUSTER_NAME" --kubernetes-version 1.37 \
  --role-arn arn:aws:iam::076548329469:role/rsoi-lab4-cluster-role \
  --resources-vpc-config "subnetIds=subnet-02e723053b5b32ea8,subnet-0a3ce1cf7effbf20b,endpointPublicAccess=true,endpointPrivateAccess=true,publicAccessCidrs=$client_ipv4/32" \
  --access-config authenticationMode=API,bootstrapClusterCreatorAdminPermissions=true \
  --upgrade-policy supportType=STANDARD --no-bootstrap-self-managed-addons \
  --tags project=rsoi-lab5
aws eks wait cluster-active --name "$EKS_CLUSTER_NAME"
aws eks update-kubeconfig --name "$EKS_CLUSTER_NAME" --alias "$KUBE_CONTEXT"

aws eks create-addon --cluster-name "$EKS_CLUSTER_NAME" \
  --addon-name eks-pod-identity-agent --addon-version v1.4.1-eksbuild.3
aws eks create-addon --cluster-name "$EKS_CLUSTER_NAME" \
  --addon-name vpc-cni --addon-version v1.22.4-eksbuild.14 \
  --pod-identity-associations '[{"serviceAccount":"aws-node","roleArn":"arn:aws:iam::076548329469:role/rsoi-lab4-vpc-cni-role"}]'
aws eks create-addon --cluster-name "$EKS_CLUSTER_NAME" \
  --addon-name kube-proxy --addon-version v1.37.0-eksbuild.39
aws eks create-addon --cluster-name "$EKS_CLUSTER_NAME" \
  --addon-name coredns --addon-version v1.14.7-eksbuild.35
aws eks create-addon --cluster-name "$EKS_CLUSTER_NAME" \
  --addon-name aws-ebs-csi-driver --addon-version v1.68.1-eksbuild.1 \
  --pod-identity-associations '[{"serviceAccount":"ebs-csi-controller-sa","roleArn":"arn:aws:iam::076548329469:role/rsoi-lab4-ebs-csi-role"}]'
aws eks create-pod-identity-association --cluster-name "$EKS_CLUSTER_NAME" \
  --namespace kube-system --service-account aws-load-balancer-controller \
  --role-arn arn:aws:iam::076548329469:role/rsoi-lab4-load-balancer-controller-role
aws eks create-nodegroup --cluster-name "$EKS_CLUSTER_NAME" \
  --nodegroup-name rsoi-lab5-workers-c7i \
  --node-role arn:aws:iam::076548329469:role/rsoi-lab4-node-role \
  --subnets subnet-02e723053b5b32ea8 subnet-0a3ce1cf7effbf20b \
  --instance-types c7i-flex.large --ami-type AL2023_x86_64_STANDARD \
  --capacity-type ON_DEMAND --disk-size 30 \
  --scaling-config minSize=2,maxSize=2,desiredSize=2 \
  --update-config maxUnavailable=1 --node-repair-config enabled=false \
  --tags project=rsoi-lab5
aws eks wait nodegroup-active --cluster-name "$EKS_CLUSTER_NAME" \
  --nodegroup-name rsoi-lab5-workers-c7i
kubectl --context "$KUBE_CONTEXT" get nodes
kubectl --context "$KUBE_CONTEXT" apply -f backend/deploy/aws/storageclass.yaml
helm upgrade --install aws-load-balancer-controller aws-load-balancer-controller \
  --repo https://aws.github.io/eks-charts --version 3.6.0 \
  --kube-context "$KUBE_CONTEXT" --namespace kube-system \
  --values backend/deploy/aws/load-balancer-controller.yaml --wait --timeout 5m
helm upgrade --install traefik traefik \
  --repo https://traefik.github.io/charts --version 43.0.0 \
  --kube-context "$KUBE_CONTEXT" --namespace ingress-system --create-namespace \
  --values backend/deploy/aws/traefik.yaml --wait --timeout 5m
~~~

Версии add-ons выше совместимы с EKS 1.37 на момент восстановления; перед новым
созданием сверить `aws eks describe-addon-versions --kubernetes-version 1.37`.
AWS Load Balancer Controller 3.6.0 использует существующую IAM-политику без расширения.
API доступен только с текущего IP `/32`; после смены VPN обновить publicAccessCidrs.
Официальные инструкции: [EBS CSI](https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html),
[Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-association.html),
[Load Balancer Controller](https://docs.aws.amazon.com/eks/latest/userguide/lbc-helm.html).

## Helm: приложение

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
`application.sh` использует Helm 4 `--wait=legacy` (polling вместо длинных watch).
При обрывах HTTP/2 через VPN запускать команды с
`DISABLE_HTTP2=true GODEBUG=http2client=0` (client-go и стандартный Go transport);
это выбирает HTTP/1.1, не отключая TLS или проверку сертификатов.
Если локальный Helm продолжает зависать, предусмотрен одноразовый
`aws/app-deploy-job.yaml`: Helm выполняется внутри кластера из закреплённого образа
прежнего runner. Bundle содержит только `helm/service` и `helm/values`, без `.env`;
он монтируется как `lab5-app-chart-bundle/charts.tar.gz`. После выполнения удалить
Job, одноимённые Role/RoleBinding/ServiceAccount и bundle ConfigMap. При выполненном
27.11 деплое эти временные ресурсы удалены; текущие Helm-релизы имеют статус deployed.

## CI и тесты задания

`classroom.yml`: build/unit/Helm и тесты Newman runner для PR/push; реальная
Auth0-интеграция — только доверенный `master` (push или workflow_dispatch).
GitHub-hosted runner поднимает отдельный Compose project со свежими volumes,
ждёт health всех сервисов, запускает 14 запросов обычным шагом с окружением job;
Classroom grader оценивает только очищенный отчёт и результат шага (10 баллов),
публикует очищенный JUnit и удаляет только ресурсы своего прогона. Нет push образов
или облачного деплоя. Отсутствующие параметры приводят к явной ошибке, не к пропуску.

В GitHub → Settings → Secrets and variables → Actions задать:

- Variables: `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_INTERNAL_AUDIENCE`,
  `OIDC_WORKER_CLIENT_ID`, `AUTH0_TEST_CLIENT_ID`.
- Secrets: `OIDC_WORKER_CLIENT_SECRET`, `AUTH0_TEST_CLIENT_SECRET`,
  `AUTH0_TEST_USERNAME`, `AUTH0_TEST_PASSWORD`.

Использовать отдельного Auth0-пользователя для тестов. После 14 запросов CI запускает
`npm run test:worker --prefix scripts`: берёт книгу, останавливает Library/Rating,
принимает возврат, проверяет Stream без JWT, перезапускает Gateway и поочерёдно
возвращает сервисы. Проверяет восстановление книги, +1 к рейтингу исходного
пользователя и пустые Stream/pending; пользовательский JWT отклоняется внутренними
API. Worker сам получает настоящий Auth0 M2M-токен. Отчёт — `worker.xml`, ошибка
проваливает job и оценку. Локально запускать только на одноразовом Compose project
с именем `lab5-worker-<уникальный суффикс>` и стандартными портами; тест останавливает
сервисы этого project. Отдельно M2M-токен скрипт не запрашивает. Перезапуск Gateway
проверяет независимость worker от исходного request context, но не моделирует
реальное истечение пользовательского JWT. Локальные Go-тесты используют HTTPS IdP
stand-in. Все отчёты очищены от credentials; тела HTTP/Redis и JWT не публикуются.
Google Sheet marker без преподавательского токена не подключён.

## Проверка ЛР5 в EKS

После деплоя на свежих тестовых данных, не одновременно с другими прогонами:

~~~bash
npm ci --prefix scripts --ignore-scripts --no-audit --no-fund
KUBE_CONTEXT=rsoi-lab5-aws KUBE_NAMESPACE=library-system \
  WORKER_TEST_ALLOW_FAILURE_INJECTION=yes \
  node --env-file=.env scripts/test-cloud.js
kubectl --context "$KUBE_CONTEXT" -n "$KUBE_NAMESPACE" get deployments
~~~

`test-cloud.js` запускает ту же коллекцию (14 запросов), затем те же 8 проверок
worker; дополнительно проверяет 401 без JWT и с повреждённым JWT на всех четырёх
сервисах. Worker проверяется через Kubernetes: временно масштабирует Library/Rating до 0,
перезапускает Gateway и восстанавливает исходное число реплик. При обычной ошибке
реплики восстанавливаются в finally; при принудительном завершении процесса
восстановить их вручную. Запуск ограничен context `rsoi-lab5-aws` и namespace
`library-system`. Пароли/JWT не передаются через публичный HTTP NLB: скрипт сам
открывает временные loopback port-forward через TLS-защищённый Kubernetes API.
Пользовательские запросы идут через Traefik/Ingress; проверки состояния — напрямую
к Service через отдельные туннели. Туннели пересоздаются после замены Pod.
Отчёты: `test-reports/newman.xml` и `worker-cloud.xml`, без HTTP-тел и credentials.
Коллекция записывает исходный рейтинг и проверяет изменение относительно него;
прогон изменяет данные, поэтому нужны доступные книги, рейтинг ниже максимума и
отсутствие чужих pending-операций. NLB остаётся HTTP-only; для обычных
внешних клиентов нужно отдельно настроить HTTPS, не отправлять туда Bearer по HTTP.
На текущем соединении `kubectl port-forward` согласовывает протокол (HTTP 101),
но SPDY-потоки не передают данные; воспроизводится на обеих нодах с kubectl
1.36.0/1.37.1/1.37.2, через WebSocket и без него. Причина на уровне VPN или
реализации SPDY окончательно не установлена. Изменять SG, отключать TLS или
копировать пользовательские secrets в Kubernetes для обхода не требуется.
`scripts/port-forward.js` использует официальный `@kubernetes/client-node` и
нативные WebSocket-каналы Kubernetes без SPDY. CA и AWS exec-аутентификация
берутся из локального kubeconfig; listener — только `127.0.0.1`. Перенаправляет
Service port в targetPort выбранного Ready Pod (для Traefik 80 → 8000).
Перед коллекцией проверяется настоящий HTTP health через каждый туннель;
неудачные POST/PATCH автоматически не повторяются. Пароль тестового пользователя
и client secret нужны только локальному Auth0 grant; в кластер они не копируются.
JWT передаётся сервисам внутри TLS-защищённого туннеля, не через публичный HTTP NLB.
Для ручных запросов/Postman (держать терминал открытым; Ctrl+C завершает туннель):

~~~bash
node scripts/port-forward.js traefik 18080
# В другом терминале:
curl --fail http://127.0.0.1:18080/manage/health
# В Postman serviceUrl = http://127.0.0.1:18080; Auth0 credentials оставить локально.
~~~

ARC-конфиги перенесены для следующего этапа: репозиторий `Nok1o/lab5_rsoi`,
scale set `lab5-cloud-runner`, образ `nok1o/lab5_rsoi:ci-runner-v1`.
Существующий `runner.sh deploy` требует предварительной настройки ARC Secret
и namespace; сейчас его выполнять не нужно.
