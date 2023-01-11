# Notes

Build in Docker
```
docker run --rm -it --entrypoint="" -v $PWD/files:/conjur_files -v $PWD:$PWD -w $PWD golang bash
go build -o /conjur_files/conjurctl ./cmd/conjurctl
```

Location of service definitions:
```sh
/etc/runit/runsvdir/default
/etc/runit/runsvdir/default/nginx/run 
/etc/runit/runsvdir/default/conjur/run

/etc/service/conjur
/etc/service/conjur/possum/run

/usr/local/bin/conjur-plugin-service
```

Location of conjur configuration + data key:
```sh
/opt/conjur/etc/possum.key
/opt/conjur/etc/conjur.conf
```

Start, stop and get status of services
```sh
sv status conjur
sv stop conjur/possum
```

Run Conjur server:
```sh
# Exec
HOME=/opt/conjur \
exec \
chpst -u conjur \
 env $(cat /opt/conjur/etc/possum.key)\
    /conjur_files/conjurctl server --port 5000

# No exec
HOME=/opt/conjur \
chpst -u conjur \
 env $(cat /opt/conjur/etc/possum.key)\
    /conjur_files/conjurctl server --port 5000
```

Location of Nginx files
```
/etc/nginx/sites-available/conjur 
/etc/conjur/nginx.d/40_possum.conf
```
