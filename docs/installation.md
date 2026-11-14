# 安装

iCloudSpace 使用一个应用容器和 PostgreSQL。以下步骤创建独立的新安装，适用于 Linux Docker Engine 和 macOS Docker Desktop。需要 Docker Compose v2、Python 3.9+、OpenSSL，以及可用的 8080 / 1993 端口。首次构建需要访问 npm、Go 模块代理和容器镜像仓库。

## 1. 准备私有配置

在仓库根目录执行，选择一个**尚不存在、位于仓库之外**的目录。每个安装必须使用不同的 Compose project 名称。

```sh
runtime="$HOME/.local/share/icloudspace"
mkdir -p "$(dirname "$runtime")"
python3 scripts/setup.py --runtime-dir "$runtime"
```

脚本先检查 Docker 中是否已有同名项目的容器或卷，并检查预期的四个卷名和默认网络名，即使这些资源没有 Compose 标签也会拒绝复用。检查通过后再生成随机数据库密码、32 字节主密钥、管理员密码、安装标识和仅用于 localhost 的 IMAPS 证书。配置与密码文件为 `0600`，目录为 `0700`；密码不会输出到终端。现有目录会被拒绝，不会覆盖已有安装。端口可通过 `--http-port 8080 --imaps-port 1993` 修改。Docker 可执行文件不在 PATH 时，可用 `DOCKER=/absolute/path/to/docker` 指定脚本使用的路径，并将其加入 PATH 后再执行后续命令。

`seed/admin-password` 保存首次登录密码，用户名为 `admin`。通过本地可信编辑器打开该文件；不要把私有目录、配置、数据库、邮件或凭据上传到代码仓库。

## 2. 构建并准备存储

以下命令中的 `runtime` 保持为第一步使用的同一目录。所有后续命令都必须使用同一份 `deployment.env`。

```sh
docker compose --env-file "$runtime/deployment.env" build app
docker compose --env-file "$runtime/deployment.env" --profile setup run --rm --no-deps provision
docker compose --env-file "$runtime/deployment.env" up -d --wait postgres
```

`provision` 仅用于首次安装：它要求配置、正文和数据库秘密卷为空，然后设置容器用户所需的权限。不要在更新时重新执行。数据库、正文、配置和数据库秘密分别保存在此 Compose project 专属的命名卷中。应用以 UID / GID `65532` 运行，PostgreSQL 不向宿主机发布端口。

如果准备或初始化中途失败，保留原目录、卷和命令输出，先核对状态；不要删除后重新执行来绕过未知结果。

## 3. 初始化并启用

```sh
docker compose --env-file "$runtime/deployment.env" run --rm --no-deps \
  --entrypoint /icloudspace-install app initialize --spec-file /run/space/initialize.json
```

成功输出包含 `state: initialized`、`result_revision: "1"` 和 `result_enabled: false`。初始化完成后，使用原安装记录中的操作编号显式启用写入：

```sh
enable_key=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["initial_enable_operation"])' "$runtime/installation.json")
docker compose --env-file "$runtime/deployment.env" run --rm --no-deps \
  --entrypoint /icloudspace-install app set-writes --process-file /run/space/process.json \
  --enabled true --expected-revision 1 --operation-key "$enable_key"
docker compose --env-file "$runtime/deployment.env" up -d --wait app
```

打开 [http://localhost:8080/admin](http://localhost:8080/admin)，使用第一步的管理员凭据登录。API 使用说明位于 [http://localhost:8080/docs/](http://localhost:8080/docs/)，OpenAPI 位于 `/openapi.json`。如果选择了其他 HTTP 端口，请相应替换链接中的端口。

首次登录后修改管理员密码，再添加自己有权管理的邮箱账户。Apple 账户能力、iCloud+ 订阅、应用专用密码及验证要求由上游决定；安装成功不会自动验证实际邮件收发能力。

命令返回 `commit_unknown` 或退出码 `3` 时，不要直接重试写命令。初始化使用 `inspect --process-file /run/space/process.json` 核对；启用写入使用原 `operation-key` 执行 `query-write-change` 查询。只有得到明确结果后再继续启动。

## HTTPS 与远程访问

默认配置仅将 HTTP 和 IMAPS 绑定到 `127.0.0.1`。生成的自签名证书仅用于本机 IMAPS，365 天后到期；它不是公网 HTTPS 证书，应用的 HTTP 监听器不直接提供 TLS。即使暂不使用 IMAPS，应用启动仍要求有效、与 `public_host` 匹配的证书和私钥。

远程部署应配置 HTTPS 反向代理和可信证书，并在首次初始化前调整 `seed/initialize.json` 中的 `public_host`、证书内容，以及 `seed/process.json` 中的 `force_secure_cookies: true`。反向代理需要保持原始 Host，并传递正确的协议；只有明确列入 `trusted_proxies` 的代理地址范围才会被信任。不要将任意来源设置为可信代理。对外发布 IMAPS 还需要单独配置网络入口和对应证书。

配置生成后，容器实际使用的是配置卷中的副本，修改宿主机 `seed/` 不会自动更新已经初始化的安装。证书续期或配置更新时，先停应用，备份配置卷，在卷内替换同一路径的文件并保持 `0600` / UID `65532`，再启动应用。持久设置的变更应通过应用支持的管理入口或明确的离线工具完成。

## 停止与诊断

```sh
docker compose --env-file "$runtime/deployment.env" ps
docker compose --env-file "$runtime/deployment.env" logs --tail 100 app
docker compose --env-file "$runtime/deployment.env" stop app
```

普通停止和重启不会删除命名卷。更新前阅读 [更新与备份](upgrading.md)。向他人提交诊断信息前，移除账号、邮箱、邮件内容、凭据和访问链接。
