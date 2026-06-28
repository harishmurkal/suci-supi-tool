package suci

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/harishmurkal/suci-supi-tool/pkg/keys"
	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

type LoadGenMode string

const (
	LoadGenModeEndToEnd    LoadGenMode = "end-to-end"
	LoadGenModeDecryptOnly LoadGenMode = "decrypt-only"
	LoadGenModeParseOnly   LoadGenMode = "parse-only"
)

type LoadGenConfig struct {
	Mode        LoadGenMode
	Scheme      suciutil.SchemeID
	N           int
	Concurrency int
	Warmup      int

	MCC        string
	MNC        string
	RoutingInd string
	MSIN       string
	KeyID      uint8
	// ProfileGSubscriberKeyID is a 5-byte subscriber key ID (10 hex chars).
	// Used when Scheme == SchemeProfileG.
	ProfileGSubscriberKeyID string
	// MLKEMSecurityLevel: 0 → ML-KEM-768; 5 → ML-KEM-1024 for schemes C–F.
	MLKEMSecurityLevel suciutil.MLKEMSecurityLevel
	// ProfileDVariant selects the Profile D wire format (baseline, add17, add19).
	// Only used when Scheme == SchemeProfileD.
	ProfileDVariant suciutil.ProfileDVariant
}

type LoadGenResult struct {
	Mode        string `json:"mode"`
	Scheme      string `json:"scheme"`
	N           int    `json:"n"`
	Concurrency int    `json:"concurrency"`
	Warmup      int    `json:"warmup"`

	NumCPU     int `json:"num_cpu"`
	GOMAXPROCS int `json:"gomaxprocs"`

	WallTimeNs int64   `json:"wall_time_ns"`
	OpsPerSec  float64 `json:"ops_per_sec"`

	Errors int `json:"errors"`

	GCs            uint32 `json:"gcs"`
	GCPauseTotalNs uint64 `json:"gc_pause_total_ns"`

	LatencyNs LoadGenLatencyNs `json:"latency_ns"`
}

type LoadGenLatencyNs struct {
	Min  int64 `json:"min"`
	P50  int64 `json:"p50"`
	P95  int64 `json:"p95"`
	P99  int64 `json:"p99"`
	Mean int64 `json:"mean"`
	Max  int64 `json:"max"`
}

type staticKeyStore struct {
	keyID  uint8
	scheme suciutil.SchemeID
	key    interface{}
}

func (s *staticKeyStore) GetPrivateKey(keyID uint8, scheme suciutil.SchemeID) (interface{}, error) {
	if keyID == s.keyID && scheme == s.scheme {
		return s.key, nil
	}
	return nil, keys.ErrKeyNotFound
}

// NormalizeLoadGenMode maps common aliases to a supported loadgen mode.
func NormalizeLoadGenMode(mode string) (LoadGenMode, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case string(LoadGenModeEndToEnd), "e2e", "endtoend":
		return LoadGenModeEndToEnd, nil
	case string(LoadGenModeDecryptOnly), "decrypt", "crypto-only", "crypto":
		return LoadGenModeDecryptOnly, nil
	case string(LoadGenModeParseOnly), "parse":
		return LoadGenModeParseOnly, nil
	default:
		return "", fmt.Errorf("invalid mode: %q (use %q, %q, or %q)", mode, LoadGenModeEndToEnd, LoadGenModeDecryptOnly, LoadGenModeParseOnly)
	}
}

func RunLoadGen(cfg LoadGenConfig) (*LoadGenResult, error) {
	if cfg.N <= 0 {
		return nil, errors.New("n must be > 0")
	}
	if cfg.Concurrency <= 0 {
		return nil, errors.New("concurrency must be > 0")
	}
	if cfg.Warmup < 0 {
		return nil, errors.New("warmup must be >= 0")
	}
	if cfg.MCC == "" {
		cfg.MCC = "001"
	}
	if cfg.MNC == "" {
		cfg.MNC = "01"
	}
	if cfg.RoutingInd == "" {
		cfg.RoutingInd = "0000"
	}
	if cfg.MSIN == "" {
		cfg.MSIN = "1234567890"
	}
	if cfg.KeyID == 0 {
		cfg.KeyID = 1
	}

	mode := cfg.Mode
	if mode == "" {
		mode = LoadGenModeEndToEnd
	}

	// Prepare a valid SUCI input and the needed crypto material.
	var (
		suciStr          string
		converter        *Converter
		cryptogram       *suciutil.Cryptogram
		pqcCryptogram    *suciutil.PQCCryptogram
		hybridCryptogram *suciutil.HybridCryptogram
		profileECg       *suciutil.ProfileECryptogram
		profileFCg       *suciutil.ProfileFCryptogram
		profileGCg       *suciutil.ProfileGCryptogram
		profileGMaterial *suciutil.ProfileGKeyMaterial
		privateKey       interface{}
		keyScheme        suciutil.SchemeID
		needKey          = cfg.Scheme == suciutil.SchemeProfileA || cfg.Scheme == suciutil.SchemeProfileB || cfg.Scheme == suciutil.SchemeProfileC || cfg.Scheme == suciutil.SchemeProfileD || cfg.Scheme == suciutil.SchemeProfileE || cfg.Scheme == suciutil.SchemeProfileF || cfg.Scheme == suciutil.SchemeProfileG
		needDecrypt      = mode == LoadGenModeEndToEnd || mode == LoadGenModeDecryptOnly
	)

	if cfg.Scheme == suciutil.SchemeNullScheme {
		msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(cfg.MSIN)
		suciStr = suciutil.ConstructSUCI(suciutil.TypeIMSI, cfg.MCC, cfg.MNC, cfg.RoutingInd, suciutil.SchemeNullScheme, 0, msinBytes)
		converter = NewConverter(keys.NewMemoryKeyStore())
	} else {
		switch cfg.Scheme {
		case suciutil.SchemeProfileA:
			keyScheme = suciutil.SchemeProfileA
		case suciutil.SchemeProfileB:
			keyScheme = suciutil.SchemeProfileB
		case suciutil.SchemeProfileC:
			keyScheme = suciutil.SchemeProfileC
		case suciutil.SchemeProfileD:
			keyScheme = suciutil.SchemeProfileD
		case suciutil.SchemeProfileE:
			keyScheme = suciutil.SchemeProfileE
		case suciutil.SchemeProfileF:
			keyScheme = suciutil.SchemeProfileF
		case suciutil.SchemeProfileG:
			keyScheme = suciutil.SchemeProfileG
		default:
			return nil, fmt.Errorf("unsupported scheme: %d", cfg.Scheme)
		}

		mlkemLevel := suciutil.NormalizeMLKEMSecurityLevel(cfg.MLKEMSecurityLevel)
		keyPair, err := keys.GenerateKeyPair(cfg.KeyID, keyScheme, mlkemLevel)
		if err != nil {
			return nil, fmt.Errorf("GenerateKeyPair failed: %w", err)
		}
		privateKey = keyPair.PrivateKey

		msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(cfg.MSIN)
		var schemeOutput []byte
		var errCode ErrorCode
		if cfg.Scheme == suciutil.SchemeProfileG {
			profileGMaterial, _ = privateKey.(*suciutil.ProfileGKeyMaterial)
			if profileGMaterial == nil {
				return nil, fmt.Errorf("invalid Profile G key material type: %T", privateKey)
			}
			rawSubID := strings.TrimSpace(cfg.ProfileGSubscriberKeyID)
			if rawSubID == "" {
				rawSubID = "0011223344"
			}
			subIDHex, err := suciutil.NormalizeProfileGSubscriberKeyID(rawSubID)
			if err != nil {
				return nil, fmt.Errorf("invalid profile-g-subscriber-key-id: %w", err)
			}
			subIDBytes, err := hex.DecodeString(subIDHex)
			if err != nil {
				return nil, fmt.Errorf("decode profile-g subscriber key ID: %w", err)
			}
			kmaster := []byte{
				0x00, 0x11, 0x22, 0x33,
				0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xaa, 0xbb,
				0xcc, 0xdd, 0xee, 0xff,
			}
			if profileGMaterial.SubscriberKeys == nil {
				profileGMaterial.SubscriberKeys = make(map[string][]byte)
			}
			profileGMaterial.SubscriberKeys[subIDHex] = kmaster
			gKeys := &suciutil.ProfileGConcealmentKeys{
				SecurityLevel:     mlkemLevel,
				HNSymmetricKey:    profileGMaterial.HNSymmetricKey,
				SubscriberKeyID:   subIDBytes,
				Kmaster:           kmaster,
				WindowSizeSeconds: profileGMaterial.WindowSizeSeconds,
			}
			schemeOutput, errCode = EncryptECIES(msinBytes, gKeys, SchemeID(cfg.Scheme), cfg.ProfileDVariant, mlkemLevel)
		} else {
			pub, err := suciutil.GetPublicKeyFromPrivate(privateKey, cfg.Scheme)
			if err != nil {
				return nil, fmt.Errorf("GetPublicKeyFromPrivate failed: %w", err)
			}
			if suciutil.SchemePQCUsesMLKEM(cfg.Scheme) {
				schemeOutput, errCode = EncryptECIES(msinBytes, pub, SchemeID(cfg.Scheme), cfg.ProfileDVariant, mlkemLevel)
			} else {
				schemeOutput, errCode = EncryptECIES(msinBytes, pub, SchemeID(cfg.Scheme), cfg.ProfileDVariant)
			}
		}
		if errCode != 0 {
			return nil, fmt.Errorf("EncryptECIES failed: %s", errCode.Error())
		}
		suciStr = suciutil.ConstructSUCI(suciutil.TypeIMSI, cfg.MCC, cfg.MNC, cfg.RoutingInd, cfg.Scheme, cfg.KeyID, schemeOutput)

		// End-to-end uses a keystore (but we keep it constant and thread-safe).
		if mode == LoadGenModeEndToEnd {
			converter = NewConverter(&staticKeyStore{keyID: cfg.KeyID, scheme: keyScheme, key: privateKey})
		}
	}

	if needDecrypt && needKey && mode == LoadGenModeDecryptOnly {
		parsed, errCode := suciutil.ParseSUCI(suciStr)
		if errCode != 0 {
			return nil, fmt.Errorf("ParseSUCI failed: %s", errCode.Error())
		}
		if cfg.Scheme == suciutil.SchemeProfileG {
			level := suciutil.NormalizeMLKEMSecurityLevel(cfg.MLKEMSecurityLevel)
			if profileGMaterial != nil {
				level = suciutil.NormalizeMLKEMSecurityLevel(profileGMaterial.SecurityLevel)
			}
			pg, ec := suciutil.ParseProfileGCryptogramForLevel(parsed.SchemeOutput, level)
			if ec != 0 {
				return nil, fmt.Errorf("ParseProfileGCryptogram failed: %s", ec.Error())
			}
			profileGCg = pg
		} else {
			parseLevel, err := suciutil.InferMLKEMSecurityLevelFromPrivateKey(privateKey, cfg.Scheme)
			if err != nil {
				return nil, fmt.Errorf("infer ML-KEM level: %w", err)
			}
			switch cfg.Scheme {
			case suciutil.SchemeProfileC:
				pqc, errCode := suciutil.ParsePQCCryptogramForLevel(parsed.SchemeOutput, parseLevel)
				if errCode != 0 {
					return nil, fmt.Errorf("ParsePQCCryptogram failed: %s", errCode.Error())
				}
				pqcCryptogram = pqc
			case suciutil.SchemeProfileD:
				hg, errCode := suciutil.ParseProfileDCryptogramForLevel(parsed.SchemeOutput, parseLevel)
				if errCode != 0 {
					return nil, fmt.Errorf("ParseProfileDCryptogram failed: %s", errCode.Error())
				}
				hybridCryptogram = hg
			case suciutil.SchemeProfileE:
				ec, errCode := suciutil.ParseProfileECryptogramForLevel(parsed.SchemeOutput, parseLevel)
				if errCode != 0 {
					return nil, fmt.Errorf("ParseProfileECryptogram failed: %s", errCode.Error())
				}
				profileECg = ec
			case suciutil.SchemeProfileF:
				fc, errCode := suciutil.ParseProfileFCryptogramForLevel(parsed.SchemeOutput, parseLevel)
				if errCode != 0 {
					return nil, fmt.Errorf("ParseProfileFCryptogram failed: %s", errCode.Error())
				}
				profileFCg = fc
			default:
				cg, errCode := suciutil.ParseCryptogram(parsed.SchemeOutput, cfg.Scheme)
				if errCode != 0 {
					return nil, fmt.Errorf("ParseCryptogram failed: %s", errCode.Error())
				}
				cryptogram = cg
			}
		}
	}

	// Warmup (not recorded)
	for i := 0; i < cfg.Warmup; i++ {
		switch mode {
		case LoadGenModeEndToEnd:
			res := converter.ConvertSUCItoSUPI(suciStr)
			if !res.IsSuccess() {
				return nil, fmt.Errorf("warmup failed: %s", res.GetErrorString())
			}
		case LoadGenModeDecryptOnly:
			var plaintext []byte
			var errCode suciutil.ErrorCode
			if cfg.Scheme == suciutil.SchemeProfileG {
				plaintext, errCode = suciutil.DecryptProfileG(profileGCg, profileGMaterial)
			} else if cfg.Scheme == suciutil.SchemeProfileC {
				plaintext, errCode = suciutil.DecryptPQC(pqcCryptogram, privateKey)
			} else if cfg.Scheme == suciutil.SchemeProfileD {
				plaintext, errCode = suciutil.DecryptHybrid(hybridCryptogram, privateKey)
			} else if cfg.Scheme == suciutil.SchemeProfileE {
				plaintext, errCode = suciutil.DecryptNestedHybrid(profileECg, privateKey)
			} else if cfg.Scheme == suciutil.SchemeProfileF {
				plaintext, errCode = suciutil.DecryptWrapperHybrid(profileFCg, privateKey)
			} else {
				plaintext, errCode = suciutil.DecryptECIES(cryptogram, privateKey, cfg.Scheme)
			}
			if errCode != 0 {
				return nil, fmt.Errorf("warmup decrypt failed: %s", errCode.Error())
			}
			if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
				return nil, fmt.Errorf("warmup DecodeMSIN_TBCD failed: %s", errCode.Error())
			}
		case LoadGenModeParseOnly:
			if _, errCode := suciutil.ParseSUCI(suciStr); errCode != 0 {
				return nil, fmt.Errorf("warmup ParseSUCI failed: %s", errCode.Error())
			}
		default:
			return nil, fmt.Errorf("unsupported mode: %s", mode)
		}
	}

	// Collect latencies via a buffered channel to avoid index races and
	// ensure only actual measured samples are used for stats.
	latChan := make(chan int64, cfg.N)
	var next uint64
	var errorsCount int64

	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	startWall := time.Now()
	var wg sync.WaitGroup
	wg.Add(cfg.Concurrency)

	for w := 0; w < cfg.Concurrency; w++ {
		go func() {
			defer wg.Done()
			for {
				i := int(atomic.AddUint64(&next, 1) - 1)
				if i >= cfg.N {
					return
				}

				start := time.Now()

				switch mode {
				case LoadGenModeEndToEnd:
					res := converter.ConvertSUCItoSUPI(suciStr)
					if !res.IsSuccess() {
						atomic.AddInt64(&errorsCount, 1)
					}

				case LoadGenModeDecryptOnly:
					var plaintext []byte
					var errCode suciutil.ErrorCode
					if cfg.Scheme == suciutil.SchemeProfileG {
						plaintext, errCode = suciutil.DecryptProfileG(profileGCg, profileGMaterial)
					} else if cfg.Scheme == suciutil.SchemeProfileC {
						plaintext, errCode = suciutil.DecryptPQC(pqcCryptogram, privateKey)
					} else if cfg.Scheme == suciutil.SchemeProfileD {
						plaintext, errCode = suciutil.DecryptHybrid(hybridCryptogram, privateKey)
					} else if cfg.Scheme == suciutil.SchemeProfileE {
						plaintext, errCode = suciutil.DecryptNestedHybrid(profileECg, privateKey)
					} else if cfg.Scheme == suciutil.SchemeProfileF {
						plaintext, errCode = suciutil.DecryptWrapperHybrid(profileFCg, privateKey)
					} else {
						plaintext, errCode = suciutil.DecryptECIES(cryptogram, privateKey, cfg.Scheme)
					}
					if errCode != 0 {
						atomic.AddInt64(&errorsCount, 1)
						break
					}
					if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
						atomic.AddInt64(&errorsCount, 1)
					}

				case LoadGenModeParseOnly:
					if _, errCode := suciutil.ParseSUCI(suciStr); errCode != 0 {
						atomic.AddInt64(&errorsCount, 1)
					}

				default:
					atomic.AddInt64(&errorsCount, 1)
				}

				// Send measured latency to channel (non-blocking since buffered).
				d := time.Since(start).Nanoseconds()
				if d == 0 {
					d = 1 // avoid zero-valued latencies which skew percentiles
				}
				latChan <- d
			}
		}()
	}

	wg.Wait()
	wall := time.Since(startWall)

	// Close the latency channel and drain into a slice for sorting/stats.
	close(latChan)
	latencies := make([]int64, 0, cfg.N)
	for v := range latChan {
		latencies = append(latencies, v)
	}

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	var gcDelta uint32
	if memAfter.NumGC >= memBefore.NumGC {
		gcDelta = memAfter.NumGC - memBefore.NumGC
	}
	var gcPauseDelta uint64
	if memAfter.PauseTotalNs >= memBefore.PauseTotalNs {
		gcPauseDelta = memAfter.PauseTotalNs - memBefore.PauseTotalNs
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	mean := int64(0)
	n := len(latencies)
	if n > 0 {
		for _, v := range latencies {
			mean += v
		}
		mean = mean / int64(n)
	}

	p := func(percent float64) int64 {
		if n == 0 {
			return 0
		}
		idx := int(math.Ceil(percent*float64(n))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= n {
			idx = n - 1
		}
		return latencies[idx]
	}

	completed := n
	opsPerSec := 0.0
	if wall.Seconds() > 0 {
		opsPerSec = float64(completed) / wall.Seconds()
	}

	schemeName := cfg.Scheme.String()
	if cfg.Scheme == suciutil.SchemeProfileD && cfg.ProfileDVariant != suciutil.ProfileDVariantBaseline {
		schemeName += " (" + cfg.ProfileDVariant.String() + ")"
	}

	res := &LoadGenResult{
		Mode:           string(mode),
		Scheme:         schemeName,
		N:              cfg.N,
		Concurrency:    cfg.Concurrency,
		Warmup:         cfg.Warmup,
		NumCPU:         runtime.NumCPU(),
		GOMAXPROCS:     runtime.GOMAXPROCS(0),
		WallTimeNs:     wall.Nanoseconds(),
		OpsPerSec:      opsPerSec,
		Errors:         int(errorsCount),
		GCs:            gcDelta,
		GCPauseTotalNs: gcPauseDelta,
		LatencyNs: LoadGenLatencyNs{
			Min: func() int64 {
				if len(latencies) == 0 {
					return 0
				}
				return latencies[0]
			}(),
			P50:  p(0.50),
			P95:  p(0.95),
			P99:  p(0.99),
			Mean: mean,
			Max: func() int64 {
				if len(latencies) == 0 {
					return 0
				}
				return latencies[len(latencies)-1]
			}(),
		},
	}

	return res, nil
}

func FormatLoadGenResultText(r *LoadGenResult) string {
	formatLatency := func(label string, ns int64, useNs bool) string {
		if useNs {
			return fmt.Sprintf("%s=%d", label, ns)
		}
		return fmt.Sprintf("%s=%.2f", label, float64(ns)/1000.0)
	}
	useNs := r.LatencyNs.Min < 1000 || r.LatencyNs.P50 < 1000
	unit := "us"
	if useNs {
		unit = "ns"
	}

	return fmt.Sprintf(
		"LoadGen Results\n"+
			"  Mode:        %s\n"+
			"  Scheme:      %s\n"+
			"  Ops:         %d (warmup: %d)\n"+
			"  Concurrency: %d\n"+
			"  Runtime:     NumCPU=%d  GOMAXPROCS=%d\n"+
			"  Wall time:   %.3f s\n"+
			"  Throughput:  %.2f ops/s\n"+
			"  Errors:      %d\n"+
			"  GC:          %d cycles, %.3f ms total pause\n"+
			"  Latency (%s): %s  %s  %s  %s  %s  %s\n",
		r.Mode,
		r.Scheme,
		r.N,
		r.Warmup,
		r.Concurrency,
		r.NumCPU,
		r.GOMAXPROCS,
		float64(r.WallTimeNs)/1e9,
		r.OpsPerSec,
		r.Errors,
		r.GCs,
		float64(r.GCPauseTotalNs)/1e6,
		unit,
		formatLatency("min", r.LatencyNs.Min, useNs),
		formatLatency("p50", r.LatencyNs.P50, useNs),
		formatLatency("p95", r.LatencyNs.P95, useNs),
		formatLatency("p99", r.LatencyNs.P99, useNs),
		formatLatency("mean", r.LatencyNs.Mean, useNs),
		formatLatency("max", r.LatencyNs.Max, useNs),
	)
}

func FormatLoadGenResultJSON(r *LoadGenResult) (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
