# 更新与备份

更新使用原安装的 `deployment.env`、数据库、正文卷、配置卷与主密钥。不要重新运行 `scripts/setup.py`、`provision` 或 `initialize`，也不要为现有数据生成新主密钥。不同安装的配置、数据库和正文不能混用。

## 1. 停止应用并禁用写入

在仓库根目录设置原私有目录，然后停止应用。PostgreSQL 保持运行。

```sh
runtime="$HOME/.local/share/icloudspace"
docker compose --env-file "$runtime/deployment.env" stop app
docker compose --env-file "$runtime/deployment.env" run --rm --no-deps \
  --entrypoint /icloudspace-install app inspect --process-file /run/space/process.json
```

记录返回的 `current_revision`。使用该值作为下面的 `revision`，为本次更新生成并保存一个操作编号：

```sh
umask 077
revision=2
update=$(mktemp -d "$runtime/update-XXXXXXXX")
python3 -c 'import uuid; print("disable-" + str(uuid.uuid4()))' > "$update/disable-operation"
disable_key=$(cat "$update/disable-operation")
docker compose --env-file "$runtime/deployment.env" run --rm --no-deps \
  --entrypoint /icloudspace-install app set-writes --process-file /run/space/process.json \
  --enabled false --expected-revision "$revision" --operation-key "$disable_key"
```

`revision=2` 只是首次新安装启用后的例子，必须替换为刚才的实际值。确认 `result_enabled: false`，记录新的修订号。`update` 指向本次更新的私有记录目录；换终端后应恢复这一原路径。若输出是未知提交，从原 `disable-operation` 文件读取编号并运行 `query-write-change --process-file /run/space/process.json --operation-key "$disable_key"`，不要生成新编号再次提交。

## 2. 保存配对备份

应用停止、写入禁用后，在仓库外创建新的私有备份目录：

```sh
umask 077
backup="$HOME/.local/share/icloudspace-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -m 700 "$backup"
docker compose --env-file "$runtime/deployment.env" exec -T postgres \
  pg_dump -U icloudspace -d icloudspace --format=custom > "$backup/database.dump"
docker compose --env-file "$runtime/deployment.env" --profile setup run --rm --no-deps \
  --entrypoint /bin/sh -v "$backup:/backup" provision -eu -c \
  'umask 077; tar -czf /backup/private-volumes.tar.gz -C / configuration content database-secrets'
cp "$runtime/deployment.env" "$runtime/installation.json" "$backup/"
docker compose --env-file "$runtime/deployment.env" images > "$backup/images.txt"
old_image=$(docker compose --env-file "$runtime/deployment.env" images -q app)
docker image save "$old_image" -o "$backup/application-image.tar"
```

确认所有命令成功且备份文件非空。数据库备份、正文、配置与主密钥构成同一恢复点，必须一起保管；备份含有敏感数据。保留此前可运行的源码版本和应用镜像，使用独立目标演练恢复后，才能将备份视为已验证的恢复方案。

## 3. 构建新版本并升级

读取目标版本的发行说明，保存上一版本，再取得所需标签或提交。仅更新应用版本时不要顺便跨 PostgreSQL 大版本更新。构建使用锁定的前端与 Go 依赖：

```sh
docker compose --env-file "$runtime/deployment.env" build app
docker compose --env-file "$runtime/deployment.env" run --rm --no-deps \
  --entrypoint /icloudspace-install app upgrade --process-file /run/space/process.json
docker compose --env-file "$runtime/deployment.env" run --rm --no-deps \
  --entrypoint /icloudspace-install app inspect --process-file /run/space/process.json
```

`upgrade` 只向前应用已定义的数据库迁移；启动应用不会自动初始化或升级数据库。若升级结果未知，运行 `query-upgrade --process-file /run/space/process.json` 查询原结果。不要自动重放。

确认升级与安装绑定成功后，使用最新 `current_revision` 和新的、保留的操作编号重新启用：

```sh
revision=3
python3 -c 'import uuid; print("enable-" + str(uuid.uuid4()))' > "$update/enable-operation"
enable_key=$(cat "$update/enable-operation")
docker compose --env-file "$runtime/deployment.env" run --rm --no-deps \
  --entrypoint /icloudspace-install app set-writes --process-file /run/space/process.json \
  --enabled true --expected-revision "$revision" --operation-key "$enable_key"
docker compose --env-file "$runtime/deployment.env" up -d --wait app
```

同样将示例 `revision` 替换为实际值。检查健康状态、管理登录、账户和邮箱列表。邮件发送与消费应另行显式验证；更新过程中不重放历史发送或结果未知的操作。

## 回退与恢复

若新版本启动失败，先停止应用并保留日志与当前数据。只有发行说明确认旧版本兼容当前数据库结构时，才可以只切回旧镜像。不要默认向后运行数据库迁移，也不要直接用旧备份覆盖更新后已产生的数据。

完整恢复应使用一个新的隔离目标，恢复同一份数据库、正文与配置备份，保留原主密钥和安装标识，再检查安装绑定和实际数据。确认恢复目标可用后再切换入口。`docker compose down -v` 会删除安装数据，不能用作普通更新或故障修复步骤。
