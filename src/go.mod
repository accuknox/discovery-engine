module github.com/accuknox/auto-policy-discovery/src

go 1.15

replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
)

require (
	github.com/DATA-DOG/go-sqlmock v1.5.0
	github.com/cilium/cilium v1.10.0
	github.com/confluentinc/confluent-kafka-go v1.6.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/go-cmp v0.5.5
	github.com/kubearmor/KubeArmor/protobuf v0.0.0-20220310101419-a9af4bd8b9f5
	github.com/robfig/cron v1.2.0
	github.com/rs/zerolog v1.25.0
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	go.mongodb.org/mongo-driver v1.5.1
	google.golang.org/grpc v1.36.1
	google.golang.org/protobuf v1.27.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/apimachinery v0.23.5
	k8s.io/client-go v0.23.5
)
