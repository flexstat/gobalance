package onionbalance

import (
	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/btime"
	"gobalance/pkg/clockwork"
	"math/rand"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var once sync.Once
var inst *onionbalance

func Onionbalance() *onionbalance {
	once.Do(func() {
		inst = &onionbalance{
			IsTestnet: false,
		}
	})
	return inst
}

type onionbalance struct {
	IsTestnet  bool
	configPath string
	configData ConfigData
	controller *Controller
	consensus  *Consensus
	services   []*Service
}

func (b *onionbalance) Consensus() *Consensus {
	return b.consensus
}

func (b *onionbalance) Controller() *Controller {
	return b.controller
}

type InitSubsystemsParams struct {
	ConfigPath  string
	IP          string
	Port        int
	Socket      string
	TorPassword string
}

func (b *onionbalance) InitSubsystems(args InitSubsystemsParams) {
	btime.Clock = clockwork.NewRealClock()
	rand.Seed(time.Now().UnixNano())
	//btime.Clock = clockwork.NewFakeClockAt(time.Now().Round(time.Hour))
	//rand.Seed(1)

	b.configPath, _ = filepath.Abs(args.ConfigPath)
	b.configData = b.LoadConfigFile()
	b.IsTestnet = false
	if b.IsTestnet {
		logrus.Warn("Onionbalance configured on a testnet!")
	}
	b.controller = NewController(args.IP, args.Port, args.TorPassword)
	b.consensus = NewConsensus(b.controller, true)

	// Initialize our service
	b.services = b.initializeServicesFromConfigData()

	// Catch interesting events (like receiving descriptors etc.)
	b.controller.AddEventListeners()
	b.controller.SetEvents()

	logrus.Warnf("Onionbalance initialized (tor version: %s)!", b.controller.GetVersion())
	logrus.Warn(strings.Repeat("=", 80))
}

func (b *onionbalance) initializeServicesFromConfigData() []*Service {
	services := make([]*Service, 0)
	for _, svc := range b.configData.Services {
		services = append(services, NewService(b.consensus, b.controller, svc, b.configPath))
	}
	return services
}

func (b *onionbalance) LoadConfigFile() (out ConfigData) {
	logrus.Infof("Loaded the config file '%s'.", b.configPath)
	_, err := toml.DecodeFile(b.configPath, &out)
	if err != nil {
		panic(err)
	}
	logrus.Debugf("Onionbalance config data: %v", out)
	return
}

// PublishAllDescriptors for each service attempt to publish all descriptors
func (b *onionbalance) PublishAllDescriptors() {
	logrus.Info("[*] PublishAllDescriptors() called [*]")

	if !b.consensus.IsLive() {
		logrus.Info("No live consensus. Waiting before publishing descriptors...")
		return
	}

	for _, svc := range b.services {
		svc.PublishDescriptors()
	}
}

func (b *onionbalance) FetchInstanceDescriptors() {
	logrus.Info("[*] FetchInstanceDescriptors() called [*]")

	// TODO: Don't do this here. Instead do it on a specialized function
	b.controller.MarkTorAsActive()

	if !b.consensus.IsLive() {
		logrus.Warn("No live consensus. Waiting before fetching descriptors...")
		return
	}

	allInstances := b.getAllInstances()

	helperFetchAllInstanceDescriptors(b.controller, allInstances)
}

// Get all instances for all services
func (b *onionbalance) getAllInstances() []*Instance {
	instances := make([]*Instance, 0)
	for _, srv := range b.services {
		instances = append(instances, srv.Instances...)
	}
	return instances
}

// Try fetch fresh descriptors for all HS instances
func helperFetchAllInstanceDescriptors(ctrl *Controller, instances []*Instance) {
	logrus.Info("Initiating fetch of descriptors for all service instances.")

	for {
		// Clear Tor descriptor cache before making fetches by sending
		// the NEWNYM singal
		ctrl.Signal("NEWNYM")
		time.Sleep(5 * time.Second)
		break
	}

	uniqueInstances := make(map[string]*Instance)
	for _, inst := range instances {
		uniqueInstances[inst.OnionAddress] = inst
	}

	for _, inst := range uniqueInstances {
		inst.FetchDescriptor()
	}
}
