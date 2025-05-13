package global

type OptionsOutputsFile struct {
	Enable   bool   `mapstructure:"enable"`
	FilePath string `mapstructure:"file_path"`
}

type OptionsOutputsKafka struct {
	Enable bool   `mapstructure:"enable"`
	Host   string `mapstructure:"host"`
	Port   uint16 `mapstructure:"port"`
	Topic  string `mapstructure:"topic"`
}

type OptionsOutputs struct {
	File  OptionsOutputsFile  `mapstructure:"file"`
	Kafka OptionsOutputsKafka `mapstructure:"kafka"`
}

type Options struct {
	// 服务配置所在的目录
	ServicesDir string `mapstructure:"services_dir"`
	// 数据推送参数
	Outputs OptionsOutputs `mapstructure:"outputs"`
}

type ServiceBaseConfig struct {
	Protocol    string `mapstructure:"protocol"`
	Application string `mapstructure:"application"`
	Enable      bool   `mapstructure:"enable"`
	Host        string `mapstructure:"host"`
	Port        uint16 `mapstructure:"port"`
}
