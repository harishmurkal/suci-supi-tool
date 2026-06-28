package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/harishmurkal/suci-supi-tool/pkg/keys"
	"github.com/harishmurkal/suci-supi-tool/pkg/slog"
	"github.com/harishmurkal/suci-supi-tool/pkg/suci"
	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

const (
	version = "2.3.0"
	banner  = `
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         SUCI-SUPI Conversion Tool                             ║
║                              Version %s                                      ║
║                      5G Security Development Tool                             ║
╚═══════════════════════════════════════════════════════════════════════════════╝
`
)

func main() {
	// Handle global flags (e.g., --debug) before subcommand parsing.
	if len(os.Args) > 1 {
		filtered := []string{os.Args[0]}
		for i := 1; i < len(os.Args); i++ {
			a := os.Args[i]
			// Accept --debug, -debug, -d anywhere on the command line
			if a == "--debug" || a == "-debug" || a == "-d" {
				slog.SetEnabled(true)
				// don't append this arg
				continue
			}
			// Accept --debug=true/false
			if strings.HasPrefix(a, "--debug=") {
				val := strings.SplitN(a, "=", 2)[1]
				if strings.ToLower(val) == "true" || val == "1" {
					slog.SetEnabled(true)
				}
				continue
			}
			// If user passed "--debug true" (separate token), accept but don't consume the next token unless it's an explicit boolean
			if a == "--debug=true" || a == "--debug=false" {
				if strings.HasSuffix(a, "=true") {
					slog.SetEnabled(true)
				}
				continue
			}
			filtered = append(filtered, a)
		}
		os.Args = filtered
	}
	// Define command-line flags for deconceal
	deconcealCmd := flag.NewFlagSet("deconceal", flag.ExitOnError)
	suciFlag := deconcealCmd.String("suci", "", "SUCI string to convert (required)")
	keyDirFlag := deconcealCmd.String("key-dir", "./keys", "Directory containing HN private keys")
	keyFileFlag := deconcealCmd.String("key-file", "", "Specific key file to use (overrides key-dir)")
	deconcealSecLevel := deconcealCmd.String("security-level", "", "For schemes C–G: optional 3 (default) or 5; must match key material for C–F and Profile-G security level for G")
	verboseFlag := deconcealCmd.Bool("verbose", false, "Enable verbose output")
	useEnvFlag := deconcealCmd.Bool("use-env", false, "Use environment variables for keys")

	// Define command-line flags for conceal
	concealCmd := flag.NewFlagSet("conceal", flag.ExitOnError)
	supiFlag := concealCmd.String("supi", "", "SUPI string to conceal (required, e.g., imsi-123450123456789)")
	concealScheme := concealCmd.String("scheme", "a", "Protection scheme: 'null', 'a', 'b', 'c' (PQC), 'd' (Hybrid), 'e' (Nested Hybrid), 'f' (Wrapper Hybrid), or 'g' (Symmetric)")
	concealKeyID := concealCmd.Int("key-id", -1, "Key ID to use (0-255, -1 for auto-select/generate)")
	concealKeyDir := concealCmd.String("key-dir", "./keys", "Directory containing HN keys")
	concealSubscriberKeyID := concealCmd.String("subscriber-key-id", "", "For scheme g: subscriber key ID (5 bytes / 10 hex chars)")
	concealRoutingInd := concealCmd.String("routing-ind", "0000", "Routing indicator (1-4 digits)")
	concealAdd17 := concealCmd.Bool("add-17", false, "[Profile D only] Use Solution #17 variant: nonce-based freshness + profile/variant binding in KDF")
	concealAdd19 := concealCmd.Bool("add-19", false, "[Profile D only] Use Solution #19 variant: AES-GCM AEAD with AAD binding")
	concealSecLevel := concealCmd.String("security-level", "3", "For schemes C–G: 3 (default) or 5; selects ML-KEM level for C–F and symmetric suite level for G")
	concealVerbose := concealCmd.Bool("verbose", false, "Enable verbose output")

	// Define command-line flags for keygen
	keygenCmd := flag.NewFlagSet("keygen", flag.ExitOnError)
	keygenOutputDir := keygenCmd.String("output-dir", "./keys", "Directory to save generated keys")
	keygenStartID := keygenCmd.Int("start-id", 0, "Starting key ID (0-255)")
	keygenEndID := keygenCmd.Int("end-id", 0, "Ending key ID (0-255), defaults to start-id")
	keygenRange := keygenCmd.String("range", "", "Key ID range (e.g., '0-255' or '0,5,10')")
	keygenProfile := keygenCmd.String("profile", "both", "Key profile: a|b|c|d|e|f|g|both|all|abc (both=A+B, all=A+B+C+D+E+F+G, abc=A+B+C)")
	keygenFormat := keygenCmd.String("format", "pem", "Output format: 'pem', 'der', 'hex', 'jwk'")
	keygenSecLevel := keygenCmd.String("security-level", "3", "For profiles c,d,e,f,g: 3 (default) or 5; for g controls HN symmetric key size/suite level")
	keygenSavePublic := keygenCmd.Bool("save-public", false, "Also save public keys")
	keygenVerbose := keygenCmd.Bool("verbose", false, "Enable verbose output")

	// Define command-line flags for inspect
	inspectCmd := flag.NewFlagSet("inspect", flag.ExitOnError)
	inspectKeyFile := inspectCmd.String("key-file", "", "Key file to inspect")
	inspectKeyDir := inspectCmd.String("key-dir", "", "Directory containing key files to inspect")
	inspectShowPublic := inspectCmd.Bool("show-public", false, "Derive and show public key from private key")
	inspectShowPrivate := inspectCmd.Bool("show-private", false, "Show private key bytes (SECURITY RISK!)")
	inspectOutput := inspectCmd.String("output", "text", "Output format: 'text' or 'json'")
	inspectRecursive := inspectCmd.Bool("recursive", false, "Recursively scan subdirectories (with --key-dir)")
	inspectShowInvalid := inspectCmd.Bool("show-invalid", false, "Show invalid/unrecognized files (with --key-dir)")

	// Define command-line flags for load generator
	loadgenCmd := flag.NewFlagSet("loadgen", flag.ExitOnError)
	loadgenMode := loadgenCmd.String("mode", "end-to-end", "Mode: 'end-to-end', 'decrypt-only', or 'parse-only'")
	loadgenScheme := loadgenCmd.String("scheme", "a", "Scheme: 'null', 'a', 'b', 'c' (PQC), 'd' (Hybrid), 'e' (Nested Hybrid), 'f' (Wrapper Hybrid), or 'g' (Symmetric)")
	loadgenN := loadgenCmd.Int("n", 100000, "Number of operations to run")
	loadgenConcurrency := loadgenCmd.Int("concurrency", runtime.GOMAXPROCS(0), "Number of worker goroutines")
	loadgenWarmup := loadgenCmd.Int("warmup", 1000, "Warmup operations (not measured)")
	loadgenMCC := loadgenCmd.String("mcc", "001", "MCC to use when generating a synthetic SUCI")
	loadgenMNC := loadgenCmd.String("mnc", "01", "MNC to use when generating a synthetic SUCI")
	loadgenRoutingInd := loadgenCmd.String("routing-ind", "0000", "Routing indicator to use when generating a synthetic SUCI")
	loadgenMSIN := loadgenCmd.String("msin", "1234567890", "MSIN to use when generating a synthetic SUCI")
	loadgenKeyID := loadgenCmd.Int("key-id", 1, "Key ID to use when generating a synthetic SUCI")
	loadgenSubscriberKeyID := loadgenCmd.String("subscriber-key-id", "", "For scheme g: subscriber key ID (5 bytes / 10 hex chars)")
	loadgenAdd17 := loadgenCmd.Bool("add-17", false, "[Profile D only] Use Solution #17 variant: nonce-based freshness + profile/variant binding in KDF")
	loadgenAdd19 := loadgenCmd.Bool("add-19", false, "[Profile D only] Use Solution #19 variant: AES-GCM AEAD with AAD binding")
	loadgenSecLevel := loadgenCmd.String("security-level", "3", "For schemes c-g: 3 or 5 (default 3)")
	loadgenOutput := loadgenCmd.String("output", "text", "Output format: 'text' or 'json'")

	// Parse command
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "deconceal":
		deconcealCmd.Parse(os.Args[2:])
		handleDeconcealCommand(
			*suciFlag,
			*keyDirFlag,
			*keyFileFlag,
			*deconcealSecLevel,
			*verboseFlag,
			*useEnvFlag,
		)

	case "conceal":
		concealCmd.Parse(os.Args[2:])
		handleConcealCommand(
			*supiFlag,
			*concealScheme,
			*concealKeyID,
			*concealKeyDir,
			*concealSubscriberKeyID,
			*concealRoutingInd,
			*concealAdd17,
			*concealAdd19,
			*concealSecLevel,
			*concealVerbose,
		)

	case "keygen":
		keygenCmd.Parse(os.Args[2:])
		handleKeygenCommand(
			*keygenOutputDir,
			*keygenStartID,
			*keygenEndID,
			*keygenRange,
			*keygenProfile,
			*keygenFormat,
			*keygenSecLevel,
			*keygenSavePublic,
			*keygenVerbose,
		)

	case "inspect":
		inspectCmd.Parse(os.Args[2:])
		handleInspectCommand(
			*inspectKeyFile,
			*inspectKeyDir,
			*inspectShowPublic,
			*inspectShowPrivate,
			*inspectOutput,
			*inspectRecursive,
			*inspectShowInvalid,
		)

	case "loadgen":
		loadgenCmd.Parse(os.Args[2:])
		handleLoadGenCommand(
			*loadgenMode,
			*loadgenScheme,
			*loadgenN,
			*loadgenConcurrency,
			*loadgenWarmup,
			*loadgenMCC,
			*loadgenMNC,
			*loadgenRoutingInd,
			*loadgenMSIN,
			*loadgenKeyID,
			*loadgenSubscriberKeyID,
			*loadgenAdd17,
			*loadgenAdd19,
			*loadgenSecLevel,
			*loadgenOutput,
		)

	case "version", "-v", "--version":
		fmt.Printf(banner, version)
		os.Exit(0)

	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)

	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func handleLoadGenCommand(mode, scheme string, n, concurrency, warmup int, mcc, mnc, routingInd, msin string, keyID int, profileGSubscriberKeyID string, add17, add19 bool, securityLevelRaw, outputFormat string) {
	// Validate output format
	if outputFormat != "text" && outputFormat != "json" {
		fmt.Printf("Error: Invalid output format '%s'. Use 'text' or 'json'\n", outputFormat)
		os.Exit(1)
	}

	parsedMode, err := suci.NormalizeLoadGenMode(mode)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Parse scheme
	var schemeID suciutil.SchemeID
	switch strings.ToLower(scheme) {
	case "null", "0":
		schemeID = suciutil.SchemeNullScheme
	case "a", "1", "profile-a", "profilea":
		schemeID = suciutil.SchemeProfileA
	case "b", "2", "profile-b", "profileb":
		schemeID = suciutil.SchemeProfileB
	case "c", "3", "profile-c", "profilec", "pqc", "mlkem":
		schemeID = suciutil.SchemeProfileC
	case "d", "4", "profile-d", "profiled", "hybrid":
		schemeID = suciutil.SchemeProfileD
	case "e", "5", "profile-e", "profilee", "nested", "nested-hybrid":
		schemeID = suciutil.SchemeProfileE
	case "f", "6", "profile-f", "profilef", "wrapper", "wrapper-hybrid":
		schemeID = suciutil.SchemeProfileF
	case "g", "7", "profile-g", "profileg", "symmetric":
		schemeID = suciutil.SchemeProfileG
	default:
		fmt.Printf("Error: Invalid scheme '%s'. Use 'null', 'a', 'b', 'c' (pqc), 'd' (hybrid), 'e' (nested hybrid), 'f' (wrapper hybrid), or 'g' (symmetric)\n", scheme)
		os.Exit(1)
	}

	if keyID < 0 || keyID > 255 {
		fmt.Println("Error: key-id must be in range 0-255")
		os.Exit(1)
	}

	mlkemLevel, err := suciutil.ParseMLKEMSecurityLevel(strings.TrimSpace(securityLevelRaw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var profileDVariant suciutil.ProfileDVariant
	if add19 {
		profileDVariant = suciutil.ProfileDVariantAdd19
	} else if add17 {
		profileDVariant = suciutil.ProfileDVariantAdd17
	}

	res, err := suci.RunLoadGen(suci.LoadGenConfig{
		Mode:                    parsedMode,
		Scheme:                  suciutil.SchemeID(schemeID),
		N:                       n,
		Concurrency:             concurrency,
		Warmup:                  warmup,
		MCC:                     mcc,
		MNC:                     mnc,
		RoutingInd:              routingInd,
		MSIN:                    msin,
		KeyID:                   uint8(keyID),
		ProfileGSubscriberKeyID: strings.TrimSpace(profileGSubscriberKeyID),
		MLKEMSecurityLevel:      mlkemLevel,
		ProfileDVariant:         profileDVariant,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if outputFormat == "json" {
		jsonOut, err := suci.FormatLoadGenResultJSON(res)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(jsonOut)
	} else {
		fmt.Print(suci.FormatLoadGenResultText(res))
	}

	if res.Errors > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

// handleDeconcealCommand handles the SUCI to SUPI de-concealment
func handleDeconcealCommand(suciStr, keyDir, keyFile, securityLevelRaw string, verbose, useEnv bool) {
	if suciStr == "" {
		fmt.Println("Error: --suci flag is required")
		os.Exit(1)
	}

	if verbose {
		fmt.Printf(banner, version)
		fmt.Printf("Converting SUCI to SUPI...\n")
		fmt.Printf("Input SUCI: %s\n\n", suciStr)
	}

	// Initialize key store based on flags
	var keyStore keys.KeyStore
	if useEnv {
		if verbose {
			fmt.Println("Using environment variables for keys")
		}
		keyStore = keys.NewEnvKeyStore()
	} else if keyFile != "" {
		if verbose {
			fmt.Printf("Using specific key file: %s\n", keyFile)
		}
		// For specific key file, use a custom one-off keystore
		keyStore = keys.NewSingleFileKeyStore(keyFile, suciStr)
	} else {
		if verbose {
			fmt.Printf("Using key directory: %s\n", keyDir)
		}
		keyStore = keys.NewFileKeyStore(keyDir)
	}

	// Create converter
	converter := suci.NewConverter(keyStore)

	var deconCfg suci.DeconcealConfig
	if strings.TrimSpace(securityLevelRaw) != "" {
		lvl, err := suciutil.ParseMLKEMSecurityLevel(strings.TrimSpace(securityLevelRaw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		deconCfg.MLKEMSecurityLevel = lvl
	}
	result := converter.ConvertSUCItoSUPIWithConfig(suciStr, deconCfg)

	// Display result
	if result.IsSuccess() {
		if verbose {
			fmt.Println("\n✓ Conversion successful!")
			fmt.Printf("SUPI: %s\n", result.SUPI)
			if sp, pe := suci.ParseSUPI(result.SUPI); pe == 0 && sp.Type == suci.TypeIMSI {
				printMSINEncodingSection(sp.MSIN, suciStr)
			}
			PrintSUCIStructureInfo(suciStr)
		} else {
			fmt.Println(result.SUPI)
		}
		os.Exit(0)
	} else {
		if verbose {
			fmt.Println("\n✗ Conversion failed!")
			fmt.Printf("Error: %s\n", result.GetErrorString())
		} else {
			fmt.Fprintf(os.Stderr, "Error: %s\n", result.GetErrorString())
		}
		os.Exit(1)
	}
}

// handleKeygenCommand handles HN key generation
func handleKeygenCommand(outputDir string, startID, endID int, rangeStr, profile, format, securityLevelRaw string, savePublic, verbose bool) {
	if verbose {
		fmt.Printf(banner, version)
		fmt.Println("Generating Home Network (HN) Keys...")
		fmt.Println()
	}

	// Validate format
	var keyFormat keys.KeyFormat
	switch strings.ToLower(format) {
	case "pem":
		keyFormat = keys.FormatPEM
	case "der":
		keyFormat = keys.FormatDER
	case "hex":
		keyFormat = keys.FormatHex
	case "jwk":
		keyFormat = keys.FormatJWK
	default:
		fmt.Printf("Error: Invalid format '%s'. Use 'pem', 'der', 'hex', or 'jwk'\n", format)
		os.Exit(1)
	}

	// Parse key ID range
	var keyIDs []int
	var err error

	if rangeStr != "" {
		keyIDs, err = parseKeyRange(rangeStr)
		if err != nil {
			fmt.Printf("Error: Invalid range format: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Use start-id and end-id
		if endID == 0 && startID >= 0 {
			endID = startID
		}
		if startID < 0 || startID > 255 || endID < 0 || endID > 255 {
			fmt.Println("Error: Key IDs must be in range 0-255")
			os.Exit(1)
		}
		if startID > endID {
			fmt.Println("Error: start-id must be less than or equal to end-id")
			os.Exit(1)
		}
		for i := startID; i <= endID; i++ {
			keyIDs = append(keyIDs, i)
		}
	}

	// Parse profile
	var schemes []suciutil.SchemeID
	switch strings.ToLower(profile) {
	case "a", "profile-a", "profilea":
		schemes = []suciutil.SchemeID{suciutil.SchemeProfileA}
	case "b", "profile-b", "profileb":
		schemes = []suciutil.SchemeID{suciutil.SchemeProfileB}
	case "c", "profile-c", "profilec", "pqc", "mlkem":
		schemes = []suciutil.SchemeID{suciutil.SchemeProfileC}
	case "both", "ab":
		schemes = []suciutil.SchemeID{suciutil.SchemeProfileA, suciutil.SchemeProfileB}
	case "d", "4", "profile-d", "profiled", "hybrid":
		schemes = []suciutil.SchemeID{suciutil.SchemeProfileD}
	case "e", "5", "profile-e", "profilee", "nested", "nested-hybrid":
		schemes = []suciutil.SchemeID{suciutil.SchemeProfileE}
	case "f", "6", "profile-f", "profilef", "wrapper", "wrapper-hybrid":
		schemes = []suciutil.SchemeID{suciutil.SchemeProfileF}
	case "g", "7", "profile-g", "profileg", "symmetric":
		schemes = []suciutil.SchemeID{suciutil.SchemeProfileG}
	case "all", "abcdef", "abcdefg":
		schemes = []suciutil.SchemeID{
			suciutil.SchemeProfileA,
			suciutil.SchemeProfileB,
			suciutil.SchemeProfileC,
			suciutil.SchemeProfileD,
			suciutil.SchemeProfileE,
			suciutil.SchemeProfileF,
			suciutil.SchemeProfileG,
		}
	case "abc":
		schemes = []suciutil.SchemeID{suciutil.SchemeProfileA, suciutil.SchemeProfileB, suciutil.SchemeProfileC}
	default:
		fmt.Printf("Error: Invalid profile '%s'. Use 'a', 'b', 'c' (pqc), 'd' (hybrid), 'e' (nested hybrid), 'f' (wrapper hybrid), 'g' (symmetric), 'both', 'all' (A+B+C+D+E+F+G), or 'abc' (A+B+C)\n", profile)
		os.Exit(1)
	}

	mlkemLevel, err := suciutil.ParseMLKEMSecurityLevel(strings.TrimSpace(securityLevelRaw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Generate keys
	totalGenerated := 0
	for _, keyID := range keyIDs {
		for _, scheme := range schemes {
			var keyPair *keys.KeyPair
			var err error
			if suciutil.SchemePQCUsesMLKEM(scheme) {
				keyPair, err = keys.GenerateKeyPair(uint8(keyID), scheme, mlkemLevel)
			} else {
				keyPair, err = keys.GenerateKeyPair(uint8(keyID), scheme)
			}
			if err != nil {
				fmt.Printf("Error generating key ID %d: %v\n", keyID, err)
				os.Exit(1)
			}

			if err := keys.SaveKeyPairWithFormat(keyPair, outputDir, savePublic, keyFormat); err != nil {
				fmt.Printf("Error saving key ID %d: %v\n", keyID, err)
				os.Exit(1)
			}

			totalGenerated++

			if verbose {
				outFmt := strings.ToUpper(format)
				if scheme == suciutil.SchemeProfileG {
					outFmt = "JSON"
				}
				fmt.Printf("  Generated: Key ID %d - %s [%s]\n", keyID, keygenProfileVerboseName(scheme, mlkemLevel), outFmt)
			}
		}
	}

	// Summary
	if verbose {
		fmt.Println()
		fmt.Printf("Successfully generated %d key(s) in '%s' [format: %s]\n", totalGenerated, outputDir, strings.ToUpper(format))
		if savePublic {
			fmt.Printf("Public keys also saved (.pub.%s files)\n", format)
		}
	} else {
		fmt.Printf("Generated %d key(s) in '%s'\n", totalGenerated, outputDir)
	}

	os.Exit(0)
}

func keygenProfileVerboseName(scheme suciutil.SchemeID, level suciutil.MLKEMSecurityLevel) string {
	l5 := suciutil.NormalizeMLKEMSecurityLevel(level) == suciutil.MLKEMSecurityLevel5
	switch scheme {
	case suciutil.SchemeProfileA:
		return "Profile A (Curve25519)"
	case suciutil.SchemeProfileB:
		return "Profile B (P-256)"
	case suciutil.SchemeProfileC:
		if l5 {
			return "Profile C (ML-KEM-1024 PQC, tool extension)"
		}
		return "Profile C (ML-KEM-768 PQC)"
	case suciutil.SchemeProfileD:
		if l5 {
			return "Profile D (Hybrid ML-KEM-1024 + X25519, tool extension)"
		}
		return "Profile D (Hybrid ML-KEM-768 + X25519)"
	case suciutil.SchemeProfileE:
		if l5 {
			return "Profile E (Nested Hybrid ML-KEM-1024 + X25519, tool extension)"
		}
		return "Profile E (Nested Hybrid ML-KEM-768 + X25519)"
	case suciutil.SchemeProfileF:
		if l5 {
			return "Profile F (Wrapper Hybrid ML-KEM-1024 + X25519, tool extension)"
		}
		return "Profile F (Wrapper Hybrid ML-KEM-768 + X25519)"
	case suciutil.SchemeProfileG:
		if l5 {
			return "Profile G (Symmetric SUCI, NIST Level 5)"
		}
		return "Profile G (Symmetric SUCI, NIST Level 3)"
	default:
		return fmt.Sprintf("Scheme %d", scheme)
	}
}

// handleConcealCommand handles the SUPI to SUCI concealment
func handleConcealCommand(supiStr, scheme string, keyID int, keyDir, profileGSubscriberKeyID, routingInd string, add17, add19 bool, securityLevelRaw string, verbose bool) {
	if supiStr == "" {
		fmt.Println("Error: --supi flag is required")
		os.Exit(1)
	}

	if verbose {
		fmt.Printf(banner, version)
		fmt.Printf("Converting SUPI to SUCI (concealment)...\n")
		fmt.Printf("Input SUPI: %s\n\n", supiStr)
	}

	// Parse scheme
	var schemeID suciutil.SchemeID
	switch strings.ToLower(scheme) {
	case "null", "0":
		schemeID = suciutil.SchemeNullScheme
	case "a", "1", "profile-a", "profilea":
		schemeID = suciutil.SchemeProfileA
	case "b", "2", "profile-b", "profileb":
		schemeID = suciutil.SchemeProfileB
	case "c", "3", "profile-c", "profilec", "pqc", "mlkem":
		schemeID = suciutil.SchemeProfileC
	case "d", "4", "profile-d", "profiled", "hybrid":
		schemeID = suciutil.SchemeProfileD
	case "e", "5", "profile-e", "profilee", "nested", "nested-hybrid":
		schemeID = suciutil.SchemeProfileE
	case "f", "6", "profile-f", "profilef", "wrapper", "wrapper-hybrid":
		schemeID = suciutil.SchemeProfileF
	case "g", "7", "profile-g", "profileg", "symmetric":
		schemeID = suciutil.SchemeProfileG
	default:
		fmt.Printf("Error: Invalid scheme '%s'. Use 'null', 'a', 'b', 'c' (pqc), 'd' (hybrid), 'e' (nested hybrid), 'f' (wrapper hybrid), or 'g' (symmetric)\n", scheme)
		os.Exit(1)
	}

	mlkemLevel, err := suciutil.ParseMLKEMSecurityLevel(strings.TrimSpace(securityLevelRaw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	l5 := suciutil.NormalizeMLKEMSecurityLevel(mlkemLevel) == suciutil.MLKEMSecurityLevel5

	if verbose {
		schemeName := "NULL-SCHEME (no encryption)"
		switch schemeID {
		case suciutil.SchemeProfileA:
			schemeName = "ECIES Profile A (Curve25519)"
		case suciutil.SchemeProfileB:
			schemeName = "ECIES Profile B (P-256)"
		case suciutil.SchemeProfileC:
			if l5 {
				schemeName = "PQC Profile C (ML-KEM-1024, tool extension)"
			} else {
				schemeName = "PQC Profile C (ML-KEM-768)"
			}
		case suciutil.SchemeProfileD:
			if l5 {
				schemeName = "Hybrid Profile D (ML-KEM-1024 + X25519, tool extension)"
			} else {
				schemeName = "Hybrid Profile D (ML-KEM-768 + X25519)"
			}
		case suciutil.SchemeProfileE:
			if l5 {
				schemeName = "Nested Hybrid Profile E (ML-KEM-1024 + X25519, tool extension)"
			} else {
				schemeName = "Nested Hybrid Profile E (ML-KEM-768 + X25519)"
			}
		case suciutil.SchemeProfileF:
			if l5 {
				schemeName = "Wrapper Hybrid Profile F (ML-KEM-1024 + X25519, tool extension)"
			} else {
				schemeName = "Wrapper Hybrid Profile F (ML-KEM-768 + X25519)"
			}
		case suciutil.SchemeProfileG:
			if l5 {
				schemeName = "Symmetric Profile G (NIST Level 5)"
			} else {
				schemeName = "Symmetric Profile G (NIST Level 3)"
			}
		}
		fmt.Printf("Protection Scheme: %s\n", schemeName)
		if keyID >= 0 {
			fmt.Printf("Key ID: %d\n", keyID)
		} else {
			fmt.Println("Key ID: Auto-select/generate")
		}
		fmt.Printf("Routing Indicator: %s\n", routingInd)
		fmt.Printf("Key Directory: %s\n", keyDir)
		if suciutil.SchemePQCUsesMLKEM(schemeID) || schemeID == suciutil.SchemeProfileG {
			if l5 {
				fmt.Println("Security level: 5")
			} else {
				fmt.Println("Security level: 3")
			}
		}
		if schemeID == suciutil.SchemeProfileG {
			fmt.Printf("Subscriber Key ID: %s\n", strings.TrimSpace(profileGSubscriberKeyID))
		}
		fmt.Println()
	}

	if schemeID == suciutil.SchemeProfileG {
		trimmed := strings.TrimSpace(profileGSubscriberKeyID)
		if trimmed == "" {
			fmt.Println("Error: --subscriber-key-id is required for scheme g (expected 10 hex chars / 5 bytes)")
			os.Exit(1)
		}
		if _, err := suciutil.NormalizeProfileGSubscriberKeyID(trimmed); err != nil {
			fmt.Printf("Error: invalid --subscriber-key-id '%s': %v\n", trimmed, err)
			fmt.Println("       The subscriber key ID must be exactly 10 hex characters (5 bytes).")
			fmt.Println("       Example: --subscriber-key-id 0011223344")
			os.Exit(1)
		}
	}

	// Initialize key store
	keyStore := keys.NewFileKeyStore(keyDir)

	// Create converter
	converter := suci.NewConverter(keyStore)

	// Profile D variant (only used when scheme is d)
	var profileDVariant suciutil.ProfileDVariant
	if add19 {
		profileDVariant = suciutil.ProfileDVariantAdd19
	} else if add17 {
		profileDVariant = suciutil.ProfileDVariantAdd17
	} else {
		profileDVariant = suciutil.ProfileDVariantBaseline
	}

	// Configure concealment
	config := suci.ConcealmentConfig{
		SUPI:                    supiStr,
		SchemeID:                suciutil.SchemeID(schemeID),
		ProfileDVariant:         profileDVariant,
		KeyID:                   keyID,
		ProfileGSubscriberKeyID: strings.TrimSpace(profileGSubscriberKeyID),
		RoutingInd:              routingInd,
		KeyDirectory:            keyDir,
		MLKEMSecurityLevel:      mlkemLevel,
	}

	// Perform concealment
	result := converter.ConvertSUPItoSUCI(config)

	// Display result
	if result.IsSuccess() {
		if verbose {
			fmt.Println("\n✓ Concealment successful!")
			fmt.Printf("SUCI: %s\n", result.SUCI)
			fmt.Printf("Key ID used: %d\n", result.KeyID)
			if sp, pe := suci.ParseSUPI(supiStr); pe == 0 && sp.Type == suci.TypeIMSI {
				printMSINEncodingSection(sp.MSIN, result.SUCI)
			}
			PrintSUCIStructureInfo(result.SUCI)
		} else {
			fmt.Println(result.SUCI)
		}
		os.Exit(0)
	} else {
		if verbose {
			fmt.Println("\n✗ Concealment failed!")
			fmt.Printf("Error: %s\n", result.GetErrorString())
		} else {
			fmt.Fprintf(os.Stderr, "Error: %s\n", result.GetErrorString())
		}
		os.Exit(1)
	}
}

// handleInspectCommand handles key file inspection
func handleInspectCommand(keyFile, keyDir string, showPublic, showPrivate bool, outputFormat string, recursive, showInvalid bool) {
	// Validate that at least one of key-file or key-dir is provided
	if keyFile == "" && keyDir == "" {
		fmt.Println("Error: --key-file or --key-dir flag is required")
		os.Exit(1)
	}

	// Cannot specify both
	if keyFile != "" && keyDir != "" {
		fmt.Println("Error: Specify either --key-file or --key-dir, not both")
		os.Exit(1)
	}

	// Validate output format
	if outputFormat != "text" && outputFormat != "json" {
		fmt.Printf("Error: Invalid output format '%s'. Use 'text' or 'json'\n", outputFormat)
		os.Exit(1)
	}

	// If a key directory is specified, inspect all key files in that directory
	if keyDir != "" {
		handleInspectDirectory(keyDir, showPublic, showPrivate, outputFormat, recursive, showInvalid)
		return
	}

	// Single file inspection (original behavior)
	// Create inspection config
	config := &keys.InspectConfig{
		KeyFile:      keyFile,
		ShowPublic:   showPublic,
		ShowPrivate:  showPrivate,
		OutputFormat: outputFormat,
	}

	// Inspect key
	info, err := keys.InspectKey(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	keys.EnrichKeyInfo(info)

	// Output result
	if outputFormat == "json" {
		jsonOutput, err := keys.FormatKeyInfoJSON(info)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(jsonOutput)
	} else {
		fmt.Print(keys.FormatKeyInfo(info))
	}

	if info.Error != "" {
		os.Exit(1)
	}
	os.Exit(0)
}

type compositeProfileSpec struct {
	suffix string
	label  string
	scheme suciutil.SchemeID
}

func buildCompositeMergedInfo(mlFile, xFile string, keyID int, keyType, profileLabel string, scheme suciutil.SchemeID, outputFormat string) *keys.KeyInfo {
	showPublic := keyType == "private"
	cfgML := &keys.InspectConfig{KeyFile: mlFile, ShowPublic: showPublic, ShowPrivate: false, OutputFormat: outputFormat}
	cfgX := &keys.InspectConfig{KeyFile: xFile, ShowPublic: showPublic, ShowPrivate: false, OutputFormat: outputFormat}
	infoML, _ := keys.InspectKey(cfgML)
	infoX, _ := keys.InspectKey(cfgX)
	if infoML == nil || infoX == nil || infoML.Error != "" || infoX.Error != "" {
		return nil
	}

	algoHybrid := "ML-KEM-768+X25519"
	if strings.Contains(infoML.Algorithm, "1024") {
		algoHybrid = "ML-KEM-1024+X25519"
	}
	merged := &keys.KeyInfo{
		FilePath:     mlFile + "," + xFile,
		FileName:     filepath.Base(mlFile) + "," + filepath.Base(xFile),
		Format:       keys.FormatPEM,
		KeyType:      keyType,
		Profile:      profileLabel,
		Scheme:       scheme,
		KeyID:        keyID,
		KeySizeBits:  infoML.KeySizeBits + infoX.KeySizeBits,
		KeySizeBytes: infoML.KeySizeBytes + infoX.KeySizeBytes,
		Algorithm:    algoHybrid,
	}

	if infoML.Fingerprint != "" && infoX.Fingerprint != "" {
		merged.Fingerprint = infoML.Fingerprint + "|" + infoX.Fingerprint
	} else if infoML.Fingerprint != "" {
		merged.Fingerprint = infoML.Fingerprint
	} else if infoX.Fingerprint != "" {
		merged.Fingerprint = infoX.Fingerprint
	}

	return merged
}

func parseCompositeSinglePrivateKeyFile(singleFile string) ([]byte, []byte, error) {
	data, err := os.ReadFile(singleFile)
	if err != nil {
		return nil, nil, err
	}

	rest := data
	var mlBytes, xBytes []byte
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if (block.Type == "ML-KEM-768 PRIVATE KEY" && len(block.Bytes) == suciutil.MLKEM768_PRIVATE_KEY_LEN) ||
			(block.Type == "ML-KEM-1024 PRIVATE KEY" && len(block.Bytes) == suciutil.MLKEM1024_PRIVATE_KEY_LEN) {
			mlBytes = block.Bytes
			continue
		}
		if block.Type == "X25519 PRIVATE KEY" && len(block.Bytes) == 32 {
			xBytes = block.Bytes
			continue
		}
		if mlBytes == nil && (len(block.Bytes) == suciutil.MLKEM768_PRIVATE_KEY_LEN || len(block.Bytes) == suciutil.MLKEM1024_PRIVATE_KEY_LEN) {
			mlBytes = block.Bytes
			continue
		}
		if len(block.Bytes) == 32 && xBytes == nil {
			xBytes = block.Bytes
			continue
		}
	}

	if mlBytes == nil || xBytes == nil {
		return nil, nil, fmt.Errorf("single composite file does not contain both ML-KEM and X25519 private key blocks")
	}

	return mlBytes, xBytes, nil
}

// handleInspectDirectory scans a directory for key files and inspects each one
func handleInspectDirectory(keyDir string, showPublic, showPrivate bool, outputFormat string, recursive, showInvalid bool) {
	// Check if directory exists
	info, err := os.Stat(keyDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Cannot access directory '%s': %v\n", keyDir, err)
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not a directory\n", keyDir)
		os.Exit(1)
	}

	// Collect all files
	var files []string
	if recursive {
		err = filepath.Walk(keyDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				files = append(files, path)
			}
			return nil
		})
	} else {
		entries, err := os.ReadDir(keyDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to read directory: %v\n", err)
			os.Exit(1)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				files = append(files, filepath.Join(keyDir, entry.Name()))
			}
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to scan directory: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Println("No files found in directory")
		os.Exit(0)
	}

	// Pre-scan files to detect composite profile pairs (D/E/F) and optional single-file composite keys.
	var results []*keys.KeyInfo
	var validCount, invalidCount int

	processed := make(map[string]bool)
	compositeProfiles := []compositeProfileSpec{
		{suffix: "d", label: "D (Hybrid ML-KEM-768+X25519)", scheme: suciutil.SchemeProfileD},
		{suffix: "e", label: "E (Nested Hybrid ML-KEM-768+X25519)", scheme: suciutil.SchemeProfileE},
		{suffix: "f", label: "F (Wrapper Hybrid ML-KEM-768+X25519)", scheme: suciutil.SchemeProfileF},
	}

	for _, profile := range compositeProfiles {
		mlkemPrivateMap := make(map[int]string)
		x25519PrivateMap := make(map[int]string)
		mlkemPublicMap := make(map[int]string)
		x25519PublicMap := make(map[int]string)
		singlePrivateMap := make(map[int]string)

		reMlPrivate := regexp.MustCompile(fmt.Sprintf(`^hn-key-(\d+)-profile-%s-mlkem\.pem$`, profile.suffix))
		reXPrivate := regexp.MustCompile(fmt.Sprintf(`^hn-key-(\d+)-profile-%s-x25519\.pem$`, profile.suffix))
		reMlPublic := regexp.MustCompile(fmt.Sprintf(`^hn-key-(\d+)-profile-%s-mlkem\.pub\.pem$`, profile.suffix))
		reXPublic := regexp.MustCompile(fmt.Sprintf(`^hn-key-(\d+)-profile-%s-x25519\.pub\.pem$`, profile.suffix))
		reSinglePrivate := regexp.MustCompile(fmt.Sprintf(`^hn-key-(\d+)-profile-%s\.pem$`, profile.suffix))

		for _, file := range files {
			base := filepath.Base(file)
			if m := reMlPrivate.FindStringSubmatch(base); len(m) == 2 {
				if id, convErr := strconv.Atoi(m[1]); convErr == nil {
					mlkemPrivateMap[id] = file
				}
				continue
			}
			if m := reXPrivate.FindStringSubmatch(base); len(m) == 2 {
				if id, convErr := strconv.Atoi(m[1]); convErr == nil {
					x25519PrivateMap[id] = file
				}
				continue
			}
			if m := reMlPublic.FindStringSubmatch(base); len(m) == 2 {
				if id, convErr := strconv.Atoi(m[1]); convErr == nil {
					mlkemPublicMap[id] = file
				}
				continue
			}
			if m := reXPublic.FindStringSubmatch(base); len(m) == 2 {
				if id, convErr := strconv.Atoi(m[1]); convErr == nil {
					x25519PublicMap[id] = file
				}
				continue
			}
			if m := reSinglePrivate.FindStringSubmatch(base); len(m) == 2 {
				if id, convErr := strconv.Atoi(m[1]); convErr == nil {
					singlePrivateMap[id] = file
				}
				continue
			}
		}

		// Create merged entries for private component pairs.
		for id, mlFile := range mlkemPrivateMap {
			xFile, ok := x25519PrivateMap[id]
			if !ok {
				continue
			}
			merged := buildCompositeMergedInfo(mlFile, xFile, id, "private", profile.label, profile.scheme, outputFormat)
			if merged == nil {
				continue
			}
			results = append(results, merged)
			// Count files consumed so summary totals stay file-accurate.
			validCount += 2
			processed[mlFile] = true
			processed[xFile] = true
		}

		// Create merged entries for public component pairs.
		for id, mlFile := range mlkemPublicMap {
			xFile, ok := x25519PublicMap[id]
			if !ok {
				continue
			}
			merged := buildCompositeMergedInfo(mlFile, xFile, id, "public", profile.label, profile.scheme, outputFormat)
			if merged == nil {
				continue
			}
			results = append(results, merged)
			validCount += 2
			processed[mlFile] = true
			processed[xFile] = true
		}

		// Support optional single-file composite private keys: hn-key-<id>-profile-{d|e|f}.pem
		for id, singleFile := range singlePrivateMap {
			if processed[singleFile] {
				continue
			}
			mlBytes, xBytes, parseErr := parseCompositeSinglePrivateKeyFile(singleFile)
			if parseErr == nil {
				combined := append(append([]byte{}, mlBytes...), xBytes...)
				sum := sha256.Sum256(combined)
				algo := "ML-KEM-768+X25519"
				if len(mlBytes) == suciutil.MLKEM1024_PRIVATE_KEY_LEN {
					algo = "ML-KEM-1024+X25519"
				}
				merged := &keys.KeyInfo{
					FilePath:     singleFile,
					FileName:     filepath.Base(singleFile),
					Format:       keys.FormatPEM,
					KeyType:      "private",
					Profile:      profile.label,
					Scheme:       profile.scheme,
					KeyID:        id,
					KeySizeBits:  8 * (len(mlBytes) + len(xBytes)),
					KeySizeBytes: len(mlBytes) + len(xBytes),
					Algorithm:    algo,
					Fingerprint:  hex.EncodeToString(sum[:]),
				}
				results = append(results, merged)
				validCount++
				processed[singleFile] = true
				continue
			}

			if showInvalid {
				info, _ := keys.InspectKey(&keys.InspectConfig{KeyFile: singleFile, ShowPublic: showPublic, ShowPrivate: showPrivate, OutputFormat: outputFormat})
				results = append(results, info)
			}
			invalidCount++
		}
	}

	// Inspect remaining files (skip processed ones)
	for _, file := range files {
		if processed[file] {
			continue
		}
		config := &keys.InspectConfig{
			KeyFile:      file,
			ShowPublic:   showPublic,
			ShowPrivate:  showPrivate,
			OutputFormat: outputFormat,
		}

		keyInfo, _ := keys.InspectKey(config)
		if keyInfo.Error == "" && keyInfo.Profile != "" {
			validCount++
			results = append(results, keyInfo)
		} else {
			invalidCount++
			if showInvalid {
				results = append(results, keyInfo)
			}
		}
	}

	// Enrich all results with OID, entropy, integrity, coordinates, quantum metrics
	for _, r := range results {
		keys.EnrichKeyInfo(r)
	}

	// Output results
	if outputFormat == "json" {
		outputDirectoryJSON(results, keyDir, validCount, invalidCount, showInvalid)
	} else {
		outputDirectoryText(results, keyDir, validCount, invalidCount, showInvalid)
	}
}

// outputDirectoryText outputs directory scan results in text format
func outputDirectoryText(results []*keys.KeyInfo, keyDir string, validCount, invalidCount int, showInvalid bool) {
	fmt.Printf("╔═══════════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║                           Key Directory Scan                                  ║\n")
	fmt.Printf("╚═══════════════════════════════════════════════════════════════════════════════╝\n\n")
	fmt.Printf("Directory: %s\n", keyDir)
	fmt.Printf("Total Files: %d | Valid Keys: %d | Invalid/Skipped: %d\n\n", validCount+invalidCount, validCount, invalidCount)

	if len(results) == 0 {
		fmt.Println("No valid key files found.")
		return
	}

	// Group by profile
	profileA := []*keys.KeyInfo{}
	profileB := []*keys.KeyInfo{}
	profileC := []*keys.KeyInfo{}
	profileD := []*keys.KeyInfo{}
	profileE := []*keys.KeyInfo{}
	profileF := []*keys.KeyInfo{}
	profileG := []*keys.KeyInfo{}
	invalid := []*keys.KeyInfo{}

	for _, info := range results {
		if info == nil || info.Error != "" || info.Profile == "" {
			invalid = append(invalid, info)
			continue
		}

		switch info.Scheme {
		case suciutil.SchemeProfileA:
			profileA = append(profileA, info)
		case suciutil.SchemeProfileB:
			profileB = append(profileB, info)
		case suciutil.SchemeProfileC:
			profileC = append(profileC, info)
		case suciutil.SchemeProfileD:
			profileD = append(profileD, info)
		case suciutil.SchemeProfileE:
			profileE = append(profileE, info)
		case suciutil.SchemeProfileF:
			profileF = append(profileF, info)
		case suciutil.SchemeProfileG:
			profileG = append(profileG, info)
		default:
			// Backward-compatible fallback for any unexpected profile strings.
			if strings.Contains(info.Profile, "Curve25519") || strings.Contains(info.Profile, "X25519") {
				profileA = append(profileA, info)
			} else if strings.Contains(info.Profile, "P-256") {
				profileB = append(profileB, info)
			} else if strings.Contains(info.Profile, "ML-KEM") || strings.Contains(info.Profile, "Profile C") {
				profileC = append(profileC, info)
			} else {
				invalid = append(invalid, info)
			}
		}
	}

	// Print Profile A keys
	if len(profileA) > 0 {
		fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
		fmt.Printf("  Profile A Keys (Curve25519/X25519) - %d found\n", len(profileA))
		fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
		printKeyTable(profileA)
	}

	// Print Profile B keys
	if len(profileB) > 0 {
		fmt.Printf("\n═══════════════════════════════════════════════════════════════════════════════\n")
		fmt.Printf("  Profile B Keys (NIST P-256) - %d found\n", len(profileB))
		fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
		printKeyTable(profileB)
	}

	// Print Profile C keys
	if len(profileC) > 0 {
		fmt.Printf("\n═══════════════════════════════════════════════════════════════════════════════\n")
		fmt.Printf("  Profile C Keys (ML-KEM-768 / PQC) - %d found\n", len(profileC))
		fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
		printKeyTable(profileC)
	}

	// Print Profile D keys
	if len(profileD) > 0 {
		fmt.Printf("\n═══════════════════════════════════════════════════════════════════════════════\n")
		fmt.Printf("  Profile D Keys (Hybrid ML-KEM-768 + X25519) - %d found\n", len(profileD))
		fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
		printKeyTable(profileD)
	}

	// Print Profile E keys
	if len(profileE) > 0 {
		fmt.Printf("\n═══════════════════════════════════════════════════════════════════════════════\n")
		fmt.Printf("  Profile E Keys (Nested Hybrid ML-KEM-768 + X25519) - %d found\n", len(profileE))
		fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
		printKeyTable(profileE)
	}

	// Print Profile F keys
	if len(profileF) > 0 {
		fmt.Printf("\n═══════════════════════════════════════════════════════════════════════════════\n")
		fmt.Printf("  Profile F Keys (Wrapper Hybrid ML-KEM-768 + X25519) - %d found\n", len(profileF))
		fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
		printKeyTable(profileF)
	}

	// Print Profile G keys
	if len(profileG) > 0 {
		fmt.Printf("\n═══════════════════════════════════════════════════════════════════════════════\n")
		fmt.Printf("  Profile G Keys (Symmetric SUCI) - %d found\n", len(profileG))
		fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
		printKeyTable(profileG)
	}

	// Print invalid files if requested
	if len(invalid) > 0 {
		fmt.Printf("\n═══════════════════════════════════════════════════════════════════════════════\n")
		fmt.Printf("  Invalid/Unrecognized Files - %d found\n", len(invalid))
		fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
		for _, info := range invalid {
			errMsg := info.Error
			if errMsg == "" {
				errMsg = "Unknown format"
			}
			fmt.Printf("  %-40s  Error: %s\n", info.FileName, errMsg)
		}
	}

	fmt.Println()
}

// printKeyTable prints a formatted table of keys with OID, integrity and entropy columns.
func printKeyTable(keyInfos []*keys.KeyInfo) {
	fmt.Printf("  %-40s  %-8s  %-8s  %-22s  %-10s  %s\n", "Filename", "Key ID", "Type", "OID", "Integrity", "Entropy")
	fmt.Printf("  %-40s  %-8s  %-8s  %-22s  %-10s  %s\n",
		strings.Repeat("-", 40), "------", "------", strings.Repeat("-", 22), strings.Repeat("-", 9), "-------")
	for _, info := range keyInfos {
		keyIDStr := "N/A"
		if info.KeyID >= 0 {
			keyIDStr = fmt.Sprintf("%d", info.KeyID)
		}
		oid := info.OID
		if len(oid) > 22 {
			oid = oid[:19] + "..."
		}
		integrity := "-"
		if info.IntegrityOK != nil {
			if *info.IntegrityOK {
				integrity = "PASS"
			} else {
				integrity = "FAIL"
			}
		}
		entropy := "-"
		if info.EntropyPct != "" {
			// Show just the percentage for the table (e.g. "97.3%")
			if idx := strings.Index(info.EntropyPct, " "); idx > 0 {
				entropy = info.EntropyPct[:idx]
			} else {
				entropy = info.EntropyPct
			}
		}
		fmt.Printf("  %-40s  %-8s  %-8s  %-22s  %-10s  %s\n",
			truncateString(info.FileName, 40),
			keyIDStr,
			info.KeyType,
			oid,
			integrity,
			entropy,
		)
	}
}

// truncateString truncates a string to maxLen with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// outputDirectoryJSON outputs directory scan results in JSON format
func outputDirectoryJSON(results []*keys.KeyInfo, keyDir string, validCount, invalidCount int, showInvalid bool) {
	type DirectoryScanResult struct {
		Directory    string          `json:"directory"`
		TotalFiles   int             `json:"total_files"`
		ValidKeys    int             `json:"valid_keys"`
		InvalidFiles int             `json:"invalid_files"`
		Keys         []*keys.KeyInfo `json:"keys"`
	}

	output := DirectoryScanResult{
		Directory:    keyDir,
		TotalFiles:   validCount + invalidCount,
		ValidKeys:    validCount,
		InvalidFiles: invalidCount,
		Keys:         results,
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonBytes))
}

// parseKeyRange parses a key range string like "0-255" or "0,5,10,15"
func parseKeyRange(rangeStr string) ([]int, error) {
	var keyIDs []int

	// Check for range format (e.g., "0-255")
	if strings.Contains(rangeStr, "-") && !strings.Contains(rangeStr, ",") {
		parts := strings.Split(rangeStr, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid range format, use 'start-end'")
		}
		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid start value: %s", parts[0])
		}
		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid end value: %s", parts[1])
		}
		if start < 0 || start > 255 || end < 0 || end > 255 {
			return nil, fmt.Errorf("key IDs must be in range 0-255")
		}
		if start > end {
			return nil, fmt.Errorf("start must be less than or equal to end")
		}
		for i := start; i <= end; i++ {
			keyIDs = append(keyIDs, i)
		}
	} else {
		// Comma-separated format (e.g., "0,5,10,15")
		parts := strings.Split(rangeStr, ",")
		for _, part := range parts {
			id, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return nil, fmt.Errorf("invalid key ID: %s", part)
			}
			if id < 0 || id > 255 {
				return nil, fmt.Errorf("key ID %d out of range (0-255)", id)
			}
			keyIDs = append(keyIDs, id)
		}
	}

	return keyIDs, nil
}

// printUsage prints the command usage information
func printUsage() {
	fmt.Printf(banner, version)
	fmt.Println("USAGE:")
	fmt.Println("  suci-supi-tool <command> [options]")
	fmt.Println()
	fmt.Println("COMMANDS:")
	fmt.Println("  conceal       Convert SUPI to SUCI (concealment - UE operation)")
	fmt.Println("  deconceal     Convert SUCI to SUPI (de-concealment - HN operation)")
	fmt.Println("  keygen        Generate Home Network (HN) key pairs")
	fmt.Println("  inspect       Inspect and analyze key files")
	fmt.Println("  loadgen       Generate load and report p50/p95/p99 latency")
	fmt.Println("  version       Show version information")
	fmt.Println("  help          Show this help message")
	fmt.Println()
	fmt.Println("CONCEAL OPTIONS (SUPI → SUCI):")
	fmt.Println("  --supi <string>       SUPI string to conceal (required, e.g., imsi-123450123456789)")
	fmt.Println("  --scheme <type>       Protection scheme: 'null', 'a', 'b', 'c' (PQC), 'd' (Hybrid), 'e', 'f', or 'g' (Symmetric)")
	fmt.Println("  --key-id <n>          Key ID to use (0-255), or -1 to auto-select/generate")
	fmt.Println("  --key-dir <path>      Directory containing HN keys")
	fmt.Println("  --subscriber-key-id   For scheme g: subscriber key ID (10 hex chars)")
	fmt.Println("  --routing-ind <ind>   Routing indicator, 1-4 digits")
	fmt.Println("  --security-level <n>  For schemes c–g: 3 (default) or 5")
	fmt.Println("  --verbose             Enable verbose output")
	fmt.Println()
	fmt.Println("DECONCEAL OPTIONS (SUCI → SUPI):")
	fmt.Println("  --suci <string>       SUCI string to convert (required)")
	fmt.Println("  --key-dir <path>      Directory containing HN private keys")
	fmt.Println("  --key-file <path>     Specific key file to use")
	fmt.Println("  --security-level <n>  Optional for schemes c–g: 3 or 5; must match HN key (omit to infer from key)")
	fmt.Println("  --use-env             Use environment variables for keys")
	fmt.Println("  --verbose             Enable verbose output")
	fmt.Println()
	fmt.Println("KEYGEN OPTIONS:")
	fmt.Println("  --output-dir <path>   Directory to save generated keys")
	fmt.Println("  --start-id <n>        Starting key ID (0-255)")
	fmt.Println("  --end-id <n>          Ending key ID (0-255). If omitted, equals --start-id")
	fmt.Println("  --range <range>       Key ID range: '0-255' or '0,5,10,15'")
	fmt.Println("  --profile <type>      Key profile: 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'both' (A+B), 'all' (A+B+C+D+E+F+G), or 'abc' (A+B+C)")
	fmt.Println("  --format <fmt>        Output format: 'pem', 'der', 'hex', 'jwk'")
	fmt.Println("  --security-level <n>  For profiles c,d,e,f,g: 3 (default) or 5")
	fmt.Println("  --save-public         Also save public keys")
	fmt.Println("  --verbose             Enable verbose output")
	fmt.Println()
	fmt.Println("INSPECT OPTIONS:")
	fmt.Println("  --key-file <path>     Single key file to inspect")
	fmt.Println("  --key-dir <path>      Directory containing key files to scan")
	fmt.Println("  --recursive           Recursively scan subdirectories (with --key-dir)")
	fmt.Println("  --show-invalid        Show invalid/unrecognized files (with --key-dir)")
	fmt.Println("  --show-public         Derive and show public key from private key")
	fmt.Println("  --show-private        Show private key bytes (SECURITY RISK!)")
	fmt.Println("  --output <fmt>        Output format: 'text' or 'json'")
	fmt.Println()
	fmt.Println("LOADGEN OPTIONS:")
	fmt.Println("  --mode <mode>         Mode: 'end-to-end', 'decrypt-only', 'parse-only'")
	fmt.Println("  --scheme <scheme>     Scheme: 'null', 'a', 'b', 'c', 'd', 'e', 'f', or 'g'")
	fmt.Println("  --n <n>               Number of operations to run")
	fmt.Println("  --concurrency <n>     Worker goroutines (defaults to GOMAXPROCS)")
	fmt.Println("  --warmup <n>          Warmup operations (not measured)")
	fmt.Println("  --mcc <mcc>           MCC used for synthetic SUCI")
	fmt.Println("  --mnc <mnc>           MNC used for synthetic SUCI")
	fmt.Println("  --routing-ind <ind>   Routing indicator to use when generating synthetic SUCI")
	fmt.Println("  --msin <msin>         MSIN used for synthetic SUCI")
	fmt.Println("  --key-id <n>          Key ID used for synthetic SUCI")
	fmt.Println("  --subscriber-key-id   For scheme g: subscriber key ID (10 hex chars)")
	fmt.Println("  --security-level <n>  For schemes c–g: 3 (default) or 5")
	fmt.Println("  --output <fmt>        Output format: 'text' or 'json'")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  # Conceal SUPI to SUCI using Profile A (auto-select or generate key)")
	fmt.Println("  suci-supi-tool conceal --supi \"imsi-123450123456789\"")
	fmt.Println()
	fmt.Println("  # Conceal with specific scheme and key ID")
	fmt.Println("  suci-supi-tool conceal --supi \"imsi-123450123456789\" --scheme b --key-id 5")
	fmt.Println()
	fmt.Println("  # Conceal with NULL scheme (no encryption)")
	fmt.Println("  suci-supi-tool conceal --supi \"imsi-123450123456789\" --scheme null")
	fmt.Println()
	fmt.Println("  # Conceal with Profile D (Hybrid PQC + X25519)")
	fmt.Println("  suci-supi-tool keygen --profile d --start-id 1 --save-public")
	fmt.Println("  suci-supi-tool conceal --supi \"imsi-123450123456789\" --scheme d --key-id 1")
	fmt.Println()
	fmt.Println("  # Generate a single key pair (Profile A and B) for Key ID 1")
	fmt.Println("  suci-supi-tool keygen --start-id 1")
	fmt.Println()
	fmt.Println("  # Generate keys for IDs 0-255 (all possible key IDs)")
	fmt.Println("  suci-supi-tool keygen --range 0-255 --verbose")
	fmt.Println()
	fmt.Println("  # Generate only Profile A keys for IDs 0,5,10")
	fmt.Println("  suci-supi-tool keygen --range 0,5,10 --profile a")
	fmt.Println()
	fmt.Println("  # Generate Profile D (hybrid) keys")
	fmt.Println("  suci-supi-tool keygen --profile d --start-id 1 --save-public")
	fmt.Println()
	fmt.Println("  # Generate Profile G (symmetric) key files")
	fmt.Println("  suci-supi-tool keygen --profile g --start-id 1")
	fmt.Println()
	fmt.Println("  # Conceal with Profile G (requires subscriber key ID from subscriber map)")
	fmt.Println("  suci-supi-tool conceal --supi \"imsi-123450123456789\" --scheme g --key-id 1 --subscriber-key-id 0011223344")
	fmt.Println()
	fmt.Println("  # Generate keys with public keys saved")
	fmt.Println("  suci-supi-tool keygen --range 0-10 --save-public --output-dir ./my-keys")
	fmt.Println()
	fmt.Println("  # Generate keys in different formats")
	fmt.Println("  suci-supi-tool keygen --start-id 1 --format der    # Binary DER format")
	fmt.Println("  suci-supi-tool keygen --start-id 1 --format hex    # Raw hex (3GPP test vectors)")
	fmt.Println("  suci-supi-tool keygen --start-id 1 --format jwk    # JSON Web Key format")
	fmt.Println()
	fmt.Println("  # Inspect a key file")
	fmt.Println("  suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-a.pem")
	fmt.Println()
	fmt.Println("  # Inspect with public key derivation")
	fmt.Println("  suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-b.pem --show-public")
	fmt.Println()
	fmt.Println("  # Inspect with JSON output")
	fmt.Println("  suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-a.pem --output json")
	fmt.Println()
	fmt.Println("  # Load generator: 100k deconceals, report p50/p95/p99")
	fmt.Println("  suci-supi-tool loadgen --scheme a --mode end-to-end --n 100000 --concurrency 8")
	fmt.Println()
	fmt.Println("  # Load generator: crypto-only (no regex parsing)")
	fmt.Println("  suci-supi-tool loadgen --scheme a --mode decrypt-only --n 100000 --concurrency 8")
	fmt.Println()
	fmt.Println("  # NULL-SCHEME deconceal (no encryption; MSIN TBCD in scheme output)")
	fmt.Println("  suci-supi-tool deconceal --suci \"suci-0-123-45-012-0-0-1032547698\"")
	fmt.Println()
	fmt.Println("  # ECIES Profile B with key directory")
	fmt.Println("  suci-supi-tool deconceal \\")
	fmt.Println("    --suci \"suci-0-123-45-012-2-101-0253fd4d2ccb9603...\" \\")
	fmt.Println("    --key-dir ./keys")
	fmt.Println()
	fmt.Println("  # PQC Profile C de-conceal (ML-KEM-768)")
	fmt.Println("  suci-supi-tool deconceal --suci \"suci-0-123-45-012-3-101-<hex-schemeOutput>\" --key-dir ./keys")
	fmt.Println()
	fmt.Println("  # ECIES Profile A with environment variable")
	fmt.Println("  export HN_KEY_5_PROFILE_A=\"$(cat keys/hn-key-5-profile-a.pem)\"")
	fmt.Println("  suci-supi-tool deconceal \\")
	fmt.Println("    --suci \"suci-0-123-45-012-1-5-a1b2c3d4...\" \\")
	fmt.Println("    --use-env")
	fmt.Println()
	fmt.Println("  # Round-trip test (conceal then deconceal)")
	fmt.Println("  suci-supi-tool keygen --start-id 1")
	fmt.Println("  SUCI=$(suci-supi-tool conceal --supi \"imsi-123450123456789\" --key-id 1)")
	fmt.Println("  suci-supi-tool deconceal --suci \"$SUCI\"")
	fmt.Println()
	fmt.Println("  # Verbose output")
	fmt.Println("  suci-supi-tool conceal --supi \"...\" --verbose")
	fmt.Println()
	fmt.Println("SUPI FORMAT:")
	fmt.Println("  imsi-<mcc><mnc><msin>")
	fmt.Println()
	fmt.Println("  mcc  : Mobile Country Code (3 digits)")
	fmt.Println("  mnc  : Mobile Network Code (2-3 digits)")
	fmt.Println("  msin : Mobile Subscriber Identification Number (max 10 digits)")
	fmt.Println()
	fmt.Println("SUCI FORMAT:")
	fmt.Println("  suci-<type>-<mcc>-<mnc>-<routingInd>-<schemeId>-<keyId>-<schemeOutput>")
	fmt.Println()
	fmt.Println("  type         : 0 (IMSI) or 1 (NAI)")
	fmt.Println("  mcc          : Mobile Country Code (3 digits)")
	fmt.Println("  mnc          : Mobile Network Code (2-3 digits)")
	fmt.Println("  routingInd   : Routing Indicator (1-4 digits)")
	fmt.Println("  schemeId     : 0 (NULL), 1 (Profile A), 2 (Profile B), 3 (Profile C), 4 (Profile D), 5 (Profile E), 6 (Profile F), 7 (Profile G)")
	fmt.Println("  keyId        : Key identifier (0-255)")
	fmt.Println("  schemeOutput : Hex-encoded data")
	fmt.Println()
	fmt.Println("KEY MANAGEMENT:")
	fmt.Println("  Generate keys using the keygen command:")
	fmt.Println("    suci-supi-tool keygen --range 0-255 --output-dir ./keys")
	fmt.Println()
	fmt.Println("  File naming convention:")
	fmt.Println("    - hn-key-{keyID}-profile-a.pem  (Curve25519/X25519)")
	fmt.Println("    - hn-key-{keyID}-profile-b.pem  (P-256/secp256r1)")
	fmt.Println("    - hn-key-{keyID}-profile-c.pem  (ML-KEM-768 / PQC)")
	fmt.Println("    - hn-key-{keyID}-profile-d-mlkem.pem, -profile-d-x25519.pem  (Profile D hybrid)")
	fmt.Println("    - hn-key-{keyID}-profile-e-mlkem.pem, -profile-e-x25519.pem  (Profile E nested hybrid)")
	fmt.Println("    - hn-key-{keyID}-profile-f-mlkem.pem, -profile-f-x25519.pem  (Profile F wrapper hybrid)")
	fmt.Println("    - hn-key-{keyID}-profile-g.json + hn-key-{keyID}-profile-g-subscribers.json  (Profile G symmetric)")
	fmt.Println()
	fmt.Println("  Environment-based:")
	fmt.Println("    Set environment variables (PEM content expected):")
	fmt.Println("    - HN_KEY_{keyID}_PROFILE_A            (X25519 private PEM or raw 32 bytes)")
	fmt.Println("    - HN_KEY_{keyID}_PROFILE_B            (P-256 private PEM)")
	fmt.Println("    - HN_KEY_{keyID}_PROFILE_C            (ML-KEM-768 private PEM)")
	fmt.Println("    - HN_KEY_{keyID}_PROFILE_D_MLKEM      (ML-KEM-768 private PEM, part 1 of hybrid)")
	fmt.Println("    - HN_KEY_{keyID}_PROFILE_D_X25519     (X25519 private PEM, part 2 of hybrid)")
	fmt.Println("    - HN_KEY_{keyID}_PROFILE_E_MLKEM      (ML-KEM-768 private PEM, part 1 of nested hybrid)")
	fmt.Println("    - HN_KEY_{keyID}_PROFILE_E_X25519     (X25519 private PEM, part 2 of nested hybrid)")
	fmt.Println("    - HN_KEY_{keyID}_PROFILE_F_MLKEM      (ML-KEM-768 private PEM, part 1 of wrapper hybrid)")
	fmt.Println("    - HN_KEY_{keyID}_PROFILE_F_X25519     (X25519 private PEM, part 2 of wrapper hybrid)")
	fmt.Println("    Alternatively, single combined files hn-key-{keyID}-profile-{d|e|f}.pem containing both PEM blocks are supported.")
	fmt.Println()
	fmt.Println("ERROR CODES:")
	fmt.Println("  0x101 - E_PARSE_SUCI: Invalid SUCI format")
	fmt.Println("  0x102 - E_PARSE_SUPI: Invalid SUPI format")
	fmt.Println("  0x201 - E_CURVE_MISMATCH: Key curve mismatch")
	fmt.Println("  0x202 - E_TAG_MISMATCH: MAC verification failed")
	fmt.Println("  0x203 - E_INVALID_EC_KEY: Invalid EC key")
	fmt.Println("  0x204 - E_SCHEME_OUTPUT_TOO_SHORT: Insufficient data")
	fmt.Println("  0x205 - E_MSIN_ENCODING: MSIN decode failed")
	fmt.Println("  0x206 - E_INVALID_IMSI_LENGTH: IMSI length invalid")
	fmt.Println("  0x207 - E_ENCRYPTION_FAILED: Encryption failed")
	fmt.Println("  0x301 - E_INVALID_SCHEME_ID: Unsupported scheme")
	fmt.Println("  0x302 - E_INVALID_TYPE: Invalid identity type")
	fmt.Println("  0x303 - E_INVALID_KEY_ID: Invalid key ID")
	fmt.Println("  0x304 - E_UNKNOWN_KEY_ID: Key not found")
	fmt.Println("  0x305 - E_INVALID_SUBSCRIBER_KEY_ID: Invalid subscriber key ID (10 hex chars)")
	fmt.Println("  0x305 - E_INVALID_SUBSCRIBER_KEY_ID: Invalid subscriber key ID (10 hex chars)")
	fmt.Println("  0x305 - E_INVALID_SUBSCRIBER_KEY_ID: Invalid subscriber key ID (10 hex chars)")
	fmt.Println()
	fmt.Println("For more information, see README.md")
}

// --- Verbose SUCI Structure Info (display-only, no crypto) ---

type fieldEntry struct {
	Name   string
	Length int
}

type suciProfileInfo struct {
	Name          string
	SecurityLevel string
	Algorithms    string
	Fields        func(schemeOutputLen int) []fieldEntry
}

func profileGDisplayStrings(schemeOutput []byte) (name, secLevel, algorithms string) {
	if _, ec := suciutil.ParseProfileGCryptogramForLevel(schemeOutput, suciutil.MLKEMSecurityLevel5); ec == 0 {
		return "Profile G - Symmetric SUCI", "~256-bit symmetric (NIST Level 5)", "AES-256-CTR, SHA3-256 KDF, KMAC256"
	}
	return "Profile G - Symmetric SUCI", "~192-bit symmetric (NIST Level 3)", "AES-128-CTR, HKDF-SHA-256, HMAC-SHA-256"
}

func profileGStructureFields(schemeOutput []byte) []fieldEntry {
	if cg, ec := suciutil.ParseProfileGCryptogramForLevel(schemeOutput, suciutil.MLKEMSecurityLevel5); ec == 0 && cg != nil {
		return []fieldEntry{
			{"Random Value (R)", len(cg.R)},
			{"Encrypted Subscriber Key ID", len(cg.KeyCipherText)},
			{"MAC over R||KeyCipherText", len(cg.MACkey)},
			{"Encrypted MSIN (AES-CTR over TBCD)", len(cg.Ciphertext)},
			{"MAC over R||CipherText", len(cg.MACmsin)},
		}
	}
	if cg, ec := suciutil.ParseProfileGCryptogramForLevel(schemeOutput, suciutil.MLKEMSecurityLevel3); ec == 0 && cg != nil {
		return []fieldEntry{
			{"Random Value (R)", len(cg.R)},
			{"Encrypted Subscriber Key ID", len(cg.KeyCipherText)},
			{"MAC over R||KeyCipherText", len(cg.MACkey)},
			{"Encrypted MSIN (AES-CTR over TBCD)", len(cg.Ciphertext)},
			{"MAC over R||CipherText", len(cg.MACmsin)},
		}
	}
	return []fieldEntry{
		{"Random Value (R)", 0},
		{"Encrypted Subscriber Key ID", suciutil.ProfileG_KeyCipherTextLen},
		{"MAC over R||KeyCipherText", 0},
		{"Encrypted MSIN (AES-CTR over TBCD)", 0},
		{"MAC over R||CipherText", 0},
	}
}

func schemeDisplayStrings(scheme suciutil.SchemeID, schemeOutput []byte, def suciProfileInfo) (name, secLevel, algorithms string) {
	if scheme == suciutil.SchemeProfileG {
		return profileGDisplayStrings(schemeOutput)
	}
	if !suciutil.SchemePQCUsesMLKEM(scheme) {
		return def.Name, def.SecurityLevel, def.Algorithms
	}
	if suciutil.InferLikelyMLKEMLevelFromSchemeOutput(scheme, schemeOutput) != suciutil.MLKEMSecurityLevel5 {
		return def.Name, def.SecurityLevel, def.Algorithms
	}
	switch scheme {
	case suciutil.SchemeProfileC:
		return "Profile C - ML-KEM-1024 (PQC, tool extension)", "~256-bit PQC (NIST Level 5)", "ML-KEM-1024, AES-256-CTR, KMAC256"
	case suciutil.SchemeProfileD:
		return "Profile D - Hybrid ML-KEM-1024 + X25519 (tool extension)", "~256-bit hybrid (classical + PQC)", "ML-KEM-1024, X25519 ECDH, AES-256-CTR, KMAC256"
	case suciutil.SchemeProfileE:
		return "Profile E - Nested Hybrid ML-KEM-1024 + X25519 (tool extension)", "~256-bit nested hybrid", "ML-KEM-1024, X25519 ECDH, AES-256-CTR, KMAC256"
	case suciutil.SchemeProfileF:
		return "Profile F - Wrapper Hybrid ML-KEM-1024 + X25519 (tool extension)", "~256-bit wrapper hybrid", "ML-KEM-1024, X25519 ECDH, AES-256-CTR, KMAC256"
	default:
		return def.Name, def.SecurityLevel, def.Algorithms
	}
}

func pqcSchemeStructureFields(scheme suciutil.SchemeID, out []byte) []fieldEntry {
	lvl := suciutil.InferLikelyMLKEMLevelFromSchemeOutput(scheme, out)
	kem := suciutil.KEMCiphertextLen(lvl)
	kemLabel := "KEM Ciphertext (ML-KEM-768)"
	if suciutil.NormalizeMLKEMSecurityLevel(lvl) == suciutil.MLKEMSecurityLevel5 {
		kemLabel = "KEM Ciphertext (ML-KEM-1024)"
	}
	n := len(out)
	switch scheme {
	case suciutil.SchemeProfileC:
		msinLen := n - kem - suciutil.ProfileC_MAC_TAG_LEN
		if msinLen < 0 {
			msinLen = 0
		}
		return []fieldEntry{
			{kemLabel, kem},
			{"Encrypted MSIN (AES-CTR over TBCD)", msinLen},
			{"MAC Tag (KMAC256)", suciutil.ProfileC_MAC_TAG_LEN},
		}
	case suciutil.SchemeProfileE:
		fixedLen := suciutil.ProfileE_EphPubKeyLen + kem + suciutil.ProfileC_MAC_TAG_LEN + suciutil.ProfileC_MAC_TAG_LEN
		msinLen := n - fixedLen
		if msinLen < 0 {
			msinLen = 0
		}
		return []fieldEntry{
			{"ECC Ephemeral Public Key (X25519)", suciutil.ProfileE_EphPubKeyLen},
			{kemLabel, kem},
			{"KEM MAC Tag (KMAC256)", suciutil.ProfileC_MAC_TAG_LEN},
			{"Encrypted MSIN (AES-CTR over TBCD)", msinLen},
			{"MSIN MAC Tag (KMAC256)", suciutil.ProfileC_MAC_TAG_LEN},
		}
	case suciutil.SchemeProfileF:
		fixedLen := kem + suciutil.ProfileF_EncEphLen + suciutil.ProfileC_MAC_TAG_LEN + suciutil.MAC_TAG_LEN
		msinLen := n - fixedLen
		if msinLen < 0 {
			msinLen = 0
		}
		return []fieldEntry{
			{kemLabel, kem},
			{"Encrypted Ephemeral Key (X25519)", suciutil.ProfileF_EncEphLen},
			{"PQC MAC Tag (KMAC256)", suciutil.ProfileC_MAC_TAG_LEN},
			{"Encrypted MSIN (AES-CTR over TBCD)", msinLen},
			{"MAC Tag (HMAC-SHA-256)", suciutil.MAC_TAG_LEN},
		}
	default:
		return nil
	}
}

// profileDStructureFields returns a variant-accurate field layout for Profile D
// (baseline, add17, add19) using the same parsing rules as conceal/deconceal.
func profileDStructureFields(schemeOutput []byte) []fieldEntry {
	lvl := suciutil.InferLikelyMLKEMLevelFromSchemeOutput(suciutil.SchemeProfileD, schemeOutput)
	kem := suciutil.KEMCiphertextLen(lvl)
	kemLabel := "KEM Ciphertext (ML-KEM-768)"
	if suciutil.NormalizeMLKEMSecurityLevel(lvl) == suciutil.MLKEMSecurityLevel5 {
		kemLabel = "KEM Ciphertext (ML-KEM-1024)"
	}
	eph := suciutil.ProfileD_EphPubKeyLen
	cg, errCode := suciutil.ParseProfileDCryptogramForLevel(schemeOutput, lvl)
	if errCode != 0 || cg == nil {
		return profileDStructureFieldsFallback(len(schemeOutput))
	}
	switch cg.Variant {
	case suciutil.ProfileDVariantAdd17:
		return []fieldEntry{
			{kemLabel, kem},
			{"ECC Ephemeral Public Key (X25519)", eph},
			{"Variant (add17 marker 0x01)", 1},
			{"Nonce (16 bytes)", suciutil.ProfileD_Add17_NonceLen},
			{"Encrypted MSIN (AES-CTR over TBCD)", len(cg.Ciphertext)},
			{"MAC Tag (KMAC256)", len(cg.MACTag)},
		}
	case suciutil.ProfileDVariantAdd19:
		return []fieldEntry{
			{kemLabel, kem},
			{"ECC Ephemeral Public Key (X25519)", eph},
			{"Variant (add19 marker 0x02)", 1},
			{"Nonce (AES-GCM, 12 bytes)", suciutil.ProfileD_Add19_NonceLen},
			{"Encrypted MSIN (AES-256-GCM)", len(cg.Ciphertext)},
			{"AEAD Tag (AES-256-GCM)", len(cg.MACTag)},
		}
	default:
		return []fieldEntry{
			{kemLabel, kem},
			{"ECC Ephemeral Public Key (X25519)", eph},
			{"Encrypted MSIN (AES-CTR over TBCD)", len(cg.Ciphertext)},
			{"MAC Tag (KMAC256)", len(cg.MACTag)},
		}
	}
}

// profileDStructureFieldsFallback is used when ParseProfileDCryptogram fails (truncated/corrupt output).
func profileDStructureFieldsFallback(soLen int) []fieldEntry {
	min1024 := suciutil.ProfileDMinLen(suciutil.MLKEMSecurityLevel5)
	kem := suciutil.MLKEM768_CIPHERTEXT_LEN
	kemLabel := "KEM Ciphertext (ML-KEM-768)"
	if soLen >= min1024 {
		kem = suciutil.KEMCiphertextLen(suciutil.MLKEMSecurityLevel5)
		kemLabel = "KEM Ciphertext (ML-KEM-1024)"
	}
	eph := suciutil.ProfileD_EphPubKeyLen
	tail := soLen - kem - eph
	if tail < 0 {
		tail = 0
	}
	return []fieldEntry{
		{kemLabel, kem},
		{"ECC Ephemeral Public Key (X25519)", eph},
		{"Tail (unparsed; expected variant/nonce/MSIN/MAC)", tail},
	}
}

// schemeStructureFields returns the verbose field layout for parsed.SchemeOutput.
func schemeStructureFields(parsed *suciutil.ParsedSUCI) []fieldEntry {
	if parsed == nil {
		return nil
	}
	switch parsed.SchemeID {
	case suciutil.SchemeProfileD:
		return profileDStructureFields(parsed.SchemeOutput)
	case suciutil.SchemeProfileC, suciutil.SchemeProfileE, suciutil.SchemeProfileF:
		return pqcSchemeStructureFields(parsed.SchemeID, parsed.SchemeOutput)
	case suciutil.SchemeProfileG:
		return profileGStructureFields(parsed.SchemeOutput)
	}
	profile, ok := suciProfileInfoMap[parsed.SchemeID]
	if !ok {
		return nil
	}
	return profile.Fields(len(parsed.SchemeOutput))
}

var suciProfileInfoMap = map[suciutil.SchemeID]suciProfileInfo{
	suciutil.SchemeNullScheme: {
		Name:          "NULL-SCHEME (no encryption)",
		SecurityLevel: "None",
		Algorithms:    "MSIN carried as TBCD octets in scheme output",
		Fields: func(soLen int) []fieldEntry {
			return []fieldEntry{
				{"MSIN (TBCD plaintext)", soLen},
			}
		},
	},
	suciutil.SchemeProfileA: {
		Name:          "Profile A - ECIES X25519",
		SecurityLevel: "~128-bit (classical)",
		Algorithms:    "X25519 ECDH, AES-256-CTR, HMAC-SHA-256",
		Fields: func(soLen int) []fieldEntry {
			msinLen := soLen - suciutil.ProfileA_PubKeyLen - suciutil.ProfileA_MACLen
			if msinLen < 0 {
				msinLen = 0
			}
			return []fieldEntry{
				{"ECC Ephemeral Public Key (X25519)", suciutil.ProfileA_PubKeyLen},
				{"Encrypted MSIN (AES-CTR over TBCD)", msinLen},
				{"MAC Tag (HMAC-SHA-256)", suciutil.ProfileA_MACLen},
			}
		},
	},
	suciutil.SchemeProfileB: {
		Name:          "Profile B - ECIES P-256",
		SecurityLevel: "~128-bit (classical)",
		Algorithms:    "ECDH P-256, AES-256-CTR, HMAC-SHA-256",
		Fields: func(soLen int) []fieldEntry {
			// Actual output uses 65-byte uncompressed key; detect dynamically.
			pubKeyLen := 65
			if soLen < pubKeyLen+suciutil.ProfileB_MACLen {
				pubKeyLen = suciutil.ProfileB_PubKeyLen // fall back to compressed
			}
			msinLen := soLen - pubKeyLen - suciutil.ProfileB_MACLen
			if msinLen < 0 {
				msinLen = 0
			}
			return []fieldEntry{
				{"ECC Ephemeral Public Key (P-256)", pubKeyLen},
				{"Encrypted MSIN (AES-CTR over TBCD)", msinLen},
				{"MAC Tag (HMAC-SHA-256)", suciutil.ProfileB_MACLen},
			}
		},
	},
	suciutil.SchemeProfileC: {
		Name:          "Profile C - ML-KEM-768 (PQC)",
		SecurityLevel: "~192-bit (post-quantum)",
		Algorithms:    "ML-KEM-768, AES-256-CTR, KMAC256",
		Fields: func(soLen int) []fieldEntry {
			msinLen := soLen - suciutil.MLKEM768_CIPHERTEXT_LEN - suciutil.ProfileC_MAC_TAG_LEN
			if msinLen < 0 {
				msinLen = 0
			}
			return []fieldEntry{
				{"KEM Ciphertext (ML-KEM-768)", suciutil.MLKEM768_CIPHERTEXT_LEN},
				{"Encrypted MSIN (AES-CTR over TBCD)", msinLen},
				{"MAC Tag (KMAC256)", suciutil.ProfileC_MAC_TAG_LEN},
			}
		},
	},
	suciutil.SchemeProfileD: {
		Name:          "Profile D - Hybrid ML-KEM-768 + X25519",
		SecurityLevel: "~192-bit (hybrid classical + PQC)",
		Algorithms:    "ML-KEM-768, X25519 ECDH, AES-256-CTR, KMAC256",
		Fields: func(soLen int) []fieldEntry {
			msinLen := soLen - suciutil.MLKEM768_CIPHERTEXT_LEN - suciutil.ProfileD_EphPubKeyLen - suciutil.ProfileC_MAC_TAG_LEN
			if msinLen < 0 {
				msinLen = 0
			}
			return []fieldEntry{
				{"KEM Ciphertext (ML-KEM-768)", suciutil.MLKEM768_CIPHERTEXT_LEN},
				{"ECC Ephemeral Public Key (X25519)", suciutil.ProfileD_EphPubKeyLen},
				{"Encrypted MSIN (AES-CTR over TBCD)", msinLen},
				{"MAC Tag (KMAC256)", suciutil.ProfileC_MAC_TAG_LEN},
			}
		},
	},
	suciutil.SchemeProfileE: {
		Name:          "Profile E - Nested Hybrid ML-KEM-768 + X25519",
		SecurityLevel: "~192-bit (nested hybrid)",
		Algorithms:    "ML-KEM-768, X25519 ECDH, AES-256-CTR, KMAC256",
		Fields: func(soLen int) []fieldEntry {
			fixedLen := suciutil.ProfileE_EphPubKeyLen + suciutil.MLKEM768_CIPHERTEXT_LEN + suciutil.ProfileC_MAC_TAG_LEN + suciutil.ProfileC_MAC_TAG_LEN
			msinLen := soLen - fixedLen
			if msinLen < 0 {
				msinLen = 0
			}
			return []fieldEntry{
				{"ECC Ephemeral Public Key (X25519)", suciutil.ProfileE_EphPubKeyLen},
				{"KEM Ciphertext (ML-KEM-768)", suciutil.MLKEM768_CIPHERTEXT_LEN},
				{"KEM MAC Tag (KMAC256)", suciutil.ProfileC_MAC_TAG_LEN},
				{"Encrypted MSIN (AES-CTR over TBCD)", msinLen},
				{"MSIN MAC Tag (KMAC256)", suciutil.ProfileC_MAC_TAG_LEN},
			}
		},
	},
	suciutil.SchemeProfileF: {
		Name:          "Profile F - Wrapper Hybrid ML-KEM-768 + X25519",
		SecurityLevel: "~192-bit (wrapper hybrid)",
		Algorithms:    "ML-KEM-768, X25519 ECDH, AES-256-CTR, KMAC256",
		Fields: func(soLen int) []fieldEntry {
			fixedLen := suciutil.MLKEM768_CIPHERTEXT_LEN + suciutil.ProfileF_EncEphLen + suciutil.ProfileC_MAC_TAG_LEN + suciutil.MAC_TAG_LEN
			msinLen := soLen - fixedLen
			if msinLen < 0 {
				msinLen = 0
			}
			return []fieldEntry{
				{"KEM Ciphertext (ML-KEM-768)", suciutil.MLKEM768_CIPHERTEXT_LEN},
				{"Encrypted Ephemeral Key (X25519)", suciutil.ProfileF_EncEphLen},
				{"PQC MAC Tag (KMAC256)", suciutil.ProfileC_MAC_TAG_LEN},
				{"Encrypted MSIN (AES-CTR over TBCD)", msinLen},
				{"MAC Tag (HMAC-SHA-256)", suciutil.MAC_TAG_LEN},
			}
		},
	},
	suciutil.SchemeProfileG: {
		Name:          "Profile G - Symmetric SUCI",
		SecurityLevel: "NIST Level 3 or 5 (depends on key material)",
		Algorithms:    "AES-CTR, KDF, MAC (level-specific)",
		Fields: func(soLen int) []fieldEntry {
			return []fieldEntry{
				{"Random Value (R)", 0},
				{"Encrypted Subscriber Key ID", suciutil.ProfileG_KeyCipherTextLen},
				{"MAC over R||KeyCipherText", 0},
				{"Encrypted MSIN (AES-CTR over TBCD)", 0},
				{"MAC over R||CipherText", 0},
			}
		},
	},
}

// PrintSUCIStructureInfo prints a detailed SUCI structure breakdown.
// Display-only: no crypto, safe to call after conceal/deconceal completes.
func PrintSUCIStructureInfo(suciStr string) {
	parsed, errCode := suciutil.ParseSUCI(suciStr)
	if errCode != 0 || parsed == nil {
		return
	}

	profile, ok := suciProfileInfoMap[parsed.SchemeID]
	if !ok {
		return
	}
	dispName, dispSec, dispAlgo := schemeDisplayStrings(parsed.SchemeID, parsed.SchemeOutput, profile)

	supiTypeName := "IMSI"
	if parsed.Type == 1 {
		supiTypeName = "NAI"
	}

	fmt.Println()
	fmt.Println("  [SUCI STRUCTURE]")
	fmt.Printf("  ├─ SUPI Type:           %s (%d)\n", supiTypeName, parsed.Type)
	fmt.Printf("  ├─ MCC:                 %s\n", parsed.MCC)
	fmt.Printf("  ├─ MNC:                 %s\n", parsed.MNC)
	fmt.Printf("  ├─ Routing Indicator:   %s\n", parsed.RoutingInd)
	fmt.Printf("  ├─ Protection Scheme:   %s\n", dispName)
	if parsed.SchemeID == suciutil.SchemeProfileD {
		lvlD := suciutil.InferLikelyMLKEMLevelFromSchemeOutput(suciutil.SchemeProfileD, parsed.SchemeOutput)
		if cg, ec := suciutil.ParseProfileDCryptogramForLevel(parsed.SchemeOutput, lvlD); ec == 0 && cg != nil {
			fmt.Printf("  ├─ Profile D variant:   %s\n", cg.Variant.String())
		}
	}
	fmt.Printf("  ├─ HN Public Key ID:    %d\n", parsed.KeyID)
	fmt.Printf("  ├─ Security Level:      %s\n", dispSec)
	fmt.Printf("  └─ Algorithms:          %s\n", dispAlgo)

	soLen := len(parsed.SchemeOutput)
	fields := schemeStructureFields(parsed)

	fmt.Println()
	fmt.Println("  [SCHEME OUTPUT BREAKDOWN]")
	for i, f := range fields {
		connector := "├─"
		if i == len(fields)-1 {
			connector = "├─"
		}
		fmt.Printf("  %s %-32s %d bytes\n", connector, f.Name+":", f.Length)
	}
	fmt.Printf("  ├─ %-32s %d bytes\n", "Scheme Output Total:", soLen)
	fmt.Printf("  └─ %-32s %d chars\n", "Total SUCI Length:", len(suciStr))

	fmt.Println()
	fmt.Println("  [SCHEME OUTPUT BYTE LAYOUT]")
	fmt.Printf("  %-9s %-9s %s\n", "Offset", "Length", "Field")
	fmt.Printf("  %-9s %-9s %s\n", "──────", "──────", "─────────────────────────────────")
	offset := 0
	for _, f := range fields {
		fmt.Printf("  %-9d %-9d %s\n", offset, f.Length, f.Name)
		offset += f.Length
	}
	fmt.Printf("  %s\n", "──────────────────────────────────────────────────────")
	fmt.Printf("  Total: %d bytes\n", offset)
}

// msinPayloadLenFromSUCI returns the MSIN field length inside scheme output (TBCD plaintext or ciphertext).
func msinPayloadLenFromSUCI(parsed *suciutil.ParsedSUCI) int {
	if parsed == nil {
		return 0
	}
	fields := schemeStructureFields(parsed)
	for _, f := range fields {
		if strings.Contains(f.Name, "Encrypted MSIN") || strings.Contains(f.Name, "TBCD plaintext") {
			return f.Length
		}
	}
	return 0
}

// printMSINEncodingSection prints TBCD details for verbose conceal/deconceal (IMSI only).
func printMSINEncodingSection(msinDigits, suciStr string) {
	parsed, errCode := suciutil.ParseSUCI(suciStr)
	if errCode != 0 || parsed == nil {
		return
	}
	tbcd, err := suciutil.EncodeMSIN_TBCD(msinDigits)
	if err != nil {
		return
	}
	ctLen := msinPayloadLenFromSUCI(parsed)
	parts := make([]string, len(tbcd))
	for i, b := range tbcd {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	hexJoined := strings.Join(parts, " ")
	if hexJoined == "" {
		hexJoined = "(none)"
	}
	fmt.Println()
	fmt.Println("  [MSIN ENCODING]")
	fmt.Println("  Encoding: TBCD (Telephony BCD)")
	fmt.Printf("  MSIN Digits: %s\n", msinDigits)
	fmt.Printf("  Encoded Length: %d bytes\n", len(tbcd))
	fmt.Printf("  Encoded Bytes: %s\n", hexJoined)
	fmt.Printf("  Ciphertext Length: %d bytes\n", ctLen)
}
