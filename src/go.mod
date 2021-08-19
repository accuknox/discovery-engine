module github.com/accuknox/knoxAutoPolicy/src

go 1.15

replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	k8s.io/client-go => github.com/cilium/client-go v0.0.0-20201020205429-459391bae0e6
// k8s.io/client-go => github.com/cilium/client-go v0.0.0-20200725133211-0bdb134c37db
)

require (
	github.com/DATA-DOG/go-sqlmock v1.5.0
	github.com/cilium/cilium v1.9.0
	github.com/confluentinc/confluent-kafka-go v1.6.1
	github.com/go-sql-driver/mysql v1.5.0
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/google/go-cmp v0.5.3
	github.com/kubearmor/KubeArmor/protobuf v0.0.0-20210812055730-4a539401e3d9
	github.com/robfig/cron v1.2.0
	github.com/rs/zerolog v1.20.0
	github.com/spf13/viper v1.6.1
	github.com/stretchr/testify v1.6.1
	go.mongodb.org/mongo-driver v1.4.3
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b // indirect
	golang.org/x/oauth2 v0.0.0-20201109201403-9fd604954f58 // indirect
	golang.org/x/sys v0.0.0-20210113181707-4bcb84eeeb78 // indirect
	golang.org/x/text v0.3.5 // indirect
	google.golang.org/genproto v0.0.0-20210113195801-ae06605f4595 // indirect
	google.golang.org/grpc v1.35.0
	google.golang.org/protobuf v1.25.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.19.4 // indirect
	k8s.io/apimachinery v0.19.4
	k8s.io/client-go v11.0.0+incompatible
)
