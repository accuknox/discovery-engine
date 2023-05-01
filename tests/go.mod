module github.com/kubearmor/discovery-engine/tests

go 1.19

require (
	github.com/onsi/ginkgo/v2 v2.7.0
	github.com/onsi/gomega v1.24.2
	github.com/rs/zerolog v1.28.0
	k8s.io/api v0.24.3
	sigs.k8s.io/yaml v1.3.0
)

require (
	github.com/AthenZ/athenz v1.10.39
	github.com/accuknox/auto-policy-discovery/src v0.0.0-20230320081550-86bcb8b555bd
	k8s.io/apimachinery v0.24.3
	k8s.io/client-go v11.0.0+incompatible
)

replace github.com/accuknox/auto-policy-discovery/src v0.0.0-20230320081550-86bcb8b555bd => ../src

require (
	cloud.google.com/go/compute v1.14.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	github.com/99designs/keyring v1.1.6 // indirect
	github.com/DATA-DOG/go-sqlmock v1.5.0 // indirect
	github.com/DataDog/zstd v1.5.0 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/apache/pulsar-client-go v0.8.1 // indirect
	github.com/apache/pulsar-client-go/oauth2 v0.0.0-20220120090717-25e59572242e // indirect
	github.com/ardielle/ardielle-go v1.5.2 // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cavaliergopher/grab/v3 v3.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cilium/cilium v1.10.14 // indirect
	github.com/clarketm/json v1.17.1 // indirect
	github.com/confluentinc/confluent-kafka-go v1.6.1 // indirect
	github.com/danieljoos/wincred v1.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dvsekhvalnov/jose2go v0.0.0-20200901110807-248326c1351b // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/analysis v0.21.1 // indirect
	github.com/go-openapi/errors v0.20.1 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.6 // indirect
	github.com/go-openapi/loads v0.21.0 // indirect
	github.com/go-openapi/runtime v0.21.1 // indirect
	github.com/go-openapi/spec v0.20.4 // indirect
	github.com/go-openapi/strfmt v0.21.1 // indirect
	github.com/go-openapi/swag v0.19.15 // indirect
	github.com/go-openapi/validate v0.20.3 // indirect
	github.com/go-sql-driver/mysql v1.5.0 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/go-github v17.0.0+incompatible // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/googleapis/gnostic v0.5.5 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/keybase/go-keychain v0.0.0-20190712205309-48d3d31d256d // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/kubearmor/KVMService/src/types v0.0.0-20220714130113-b0eba8c9ff34 // indirect
	github.com/kubearmor/KubeArmor/protobuf v0.0.0-20220815044951-425f333210e1 // indirect
	github.com/kyverno/kyverno v1.6.10 // indirect
	github.com/linkedin/goavro/v2 v2.9.8 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-sqlite3 v1.14.12 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.0.2 // indirect
	github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.12.2 // indirect
	github.com/prometheus/client_model v0.2.1-0.20210607210712-147c58e9608a // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/robfig/cron v1.2.0 // indirect
	github.com/rogpeppe/go-internal v1.8.0 // indirect
	github.com/sasha-s/go-deadlock v0.3.1 // indirect
	github.com/shirou/gopsutil/v3 v3.21.10 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/afero v1.9.2 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/cobra v1.4.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.12.0 // indirect
	github.com/stretchr/testify v1.7.2 // indirect
	github.com/subosito/gotenv v1.4.0 // indirect
	go.mongodb.org/mongo-driver v1.8.4 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	golang.org/x/crypto v0.1.0 // indirect
	golang.org/x/net v0.5.0 // indirect
	golang.org/x/oauth2 v0.4.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.4.0 // indirect
	golang.org/x/term v0.4.0 // indirect
	golang.org/x/text v0.6.0 // indirect
	golang.org/x/time v0.0.0-20220722155302-e5dcc9cfc0b9 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20221202195650-67e5cbc046fd // indirect
	google.golang.org/grpc v1.51.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiextensions-apiserver v0.23.2 // indirect
	k8s.io/klog/v2 v2.70.1 // indirect
	k8s.io/utils v0.0.0-20220812165043-ad590609e2e5 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
)

replace (
	//cloud.google.com/go/compute/metadata => cloud.google.com/go/compute/metadata v0.2.3
	k8s.io/api => k8s.io/api v0.22.3
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.22.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.22.3
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.22.3
	k8s.io/client-go => k8s.io/client-go v0.22.3
)
