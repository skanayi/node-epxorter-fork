// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !nonetstat
// +build !nonetstat

package collector

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	netStatsSubsystem = "netstat"
)

var (
	netStatFields = kingpin.Flag("collector.netstat.fields", "Regexp of fields to return for netstat collector.").Default("^(.*_(InErrors|InErrs)|Ip_Forwarding|Ip(6|Ext)_(InOctets|OutOctets)|Icmp6?_(InMsgs|OutMsgs)|TcpExt_(Listen.*|Syncookies.*|TCPSynRetrans|TCPTimeouts)|Tcp_(ActiveOpens|InSegs|OutSegs|OutRsts|PassiveOpens|RetransSegs|CurrEstab)|Udp6?_(InDatagrams|OutDatagrams|NoPorts|RcvbufErrors|SndbufErrors))$").String()
	logger        log.Logger
)

type netStatCollector struct {
	fieldPattern *regexp.Regexp
	logger       log.Logger
}

func init() {

	registerCollector("netstat", defaultEnabled, NewNetStatCollector)
}

// NewNetStatCollector takes and returns
// a new Collector exposing network stats.
func NewNetStatCollector(logger log.Logger) (Collector, error) {
	pattern := regexp.MustCompile(*netStatFields)
	return &netStatCollector{
		fieldPattern: pattern,
		logger:       logger,
	}, nil
}

func (c *netStatCollector) Update(ch chan<- prometheus.Metric) error {
	netStats, err := getNetStats(procFilePath("net/netstat"), c.logger)
	if err != nil {
		return fmt.Errorf("couldn't get netstats: %w", err)
	}
	snmpStats, err := getNetStats(procFilePath("net/snmp"), c.logger)
	if err != nil {
		return fmt.Errorf("couldn't get SNMP stats: %w", err)
	}
	snmp6Stats, err := getSNMP6Stats(procFilePath("net/snmp6"))
	if err != nil {
		return fmt.Errorf("couldn't get SNMP6 stats: %w", err)
	}
	// Merge the results of snmpStats into netStats (collisions are possible, but
	// we know that the keys are always unique for the given use case).
	for k, v := range snmpStats {
		netStats[k] = v
	}
	for k, v := range snmp6Stats {
		netStats[k] = v
	}
	for protocol, protocolStats := range netStats {
		for name, value := range protocolStats {
			key := protocol + "_" + name
			v, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return fmt.Errorf("invalid value %s in netstats: %w", value, err)
			}
			if !c.fieldPattern.MatchString(key) {
				continue
			}
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, netStatsSubsystem, key),
					fmt.Sprintf("Statistic %s.", protocol+name),
					nil, nil,
				),
				prometheus.UntypedValue, v,
			)
		}
	}
	return nil
}

func getNetStats(fileName string, logger log.Logger) (map[string]map[string]string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseNetStats(file, fileName, logger)
}

func parseNetStats(r io.Reader, fileName string, logger log.Logger) (map[string]map[string]string, error) {

	level.Debug(logger).Log("msg", "parsing net stats for", "company", "mycom", "name", fileName)

	var (
		netStats = map[string]map[string]string{}
		scanner  = bufio.NewScanner(r)
	)

	for scanner.Scan() {
		nameParts := strings.Split(scanner.Text(), " ")
		scanner.Scan()
		valueParts := strings.Split(scanner.Text(), " ")
		level.Debug(logger).Log("msg", "parsing net stats for", "company", "mycom", "name", fileName)
		level.Debug(logger).Log("msg", "name part is", "nameparts", strings.Join(nameParts, ","), "name", fileName)
		level.Debug(logger).Log("msg", "name part zero is", "nameparts", nameParts[0], "name", fileName)

		if len(nameParts[0]) > 0 {

			// Remove trailing :.
			protocol := nameParts[0][:len(nameParts[0])-1]
			level.Debug(logger).Log("msg", "protocol is", "protocols", protocol, "name", fileName)

			netStats[protocol] = map[string]string{}
			if len(nameParts) != len(valueParts) {
				return nil, fmt.Errorf("mismatch field count mismatch in %s: %s",
					fileName, protocol)
			}
			for i := 1; i < len(nameParts); i++ {
				netStats[protocol][nameParts[i]] = valueParts[i]
			}
		} else {

			level.Debug(logger).Log("msg", "length of name space part is zero", "company", "mycom", "name", fileName)
			tmp, err := os.Create("/tmp/node_exporter_file")
			if err != nil {
				level.Debug(logger).Log("msg", "cannot create mp node exporter file", "company", "mycom", "name", fileName)
				return netStats, err
			}
			_, err = io.Copy(tmp, r)
			if err != nil {
				level.Debug(logger).Log("msg", "cannot copy to temp file", "company", "mycom", "name", fileName)
				return netStats, err
			}
			tmp.Close()
			return netStats, fmt.Errorf("length of nameparts under parseNetStats is zero %s ", fileName)

		}
	}

	return netStats, scanner.Err()
}

func getSNMP6Stats(fileName string) (map[string]map[string]string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		// On systems with IPv6 disabled, this file won't exist.
		// Do nothing.
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, err
	}
	defer file.Close()

	return parseSNMP6Stats(file)
}

func parseSNMP6Stats(r io.Reader) (map[string]map[string]string, error) {
	var (
		netStats = map[string]map[string]string{}
		scanner  = bufio.NewScanner(r)
	)

	for scanner.Scan() {
		stat := strings.Fields(scanner.Text())
		if len(stat) < 2 {
			continue
		}
		// Expect to have "6" in metric name, skip line otherwise
		if sixIndex := strings.Index(stat[0], "6"); sixIndex != -1 {
			protocol := stat[0][:sixIndex+1]
			name := stat[0][sixIndex+1:]
			if _, present := netStats[protocol]; !present {
				netStats[protocol] = map[string]string{}
			}
			netStats[protocol][name] = stat[1]
		}
	}

	return netStats, scanner.Err()
}
