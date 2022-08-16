set -e

/bin/systemctl daemon-reload
/bin/systemctl start knoxAutoPolicy.service
