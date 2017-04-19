package check

import (
	"bytes"
	_ "crypto/sha512" // for tls cipher support
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	mathrand "math/rand"
	"net/http"
	"net/http/httputil"
	"runtime"
	"time"

	"github.com/getlantern/flashlight/proxied"
	"github.com/getlantern/go-update"
	"github.com/getlantern/golog"
	"github.com/kardianos/osext"
)

type Initiative string

const (
	INITIATIVE_NEVER  Initiative = "never"
	INITIATIVE_AUTO              = "auto"
	INITIATIVE_MANUAL            = "manual"
)

var (
	log = golog.LoggerFor("go-update.check")
)

var (
	ErrNoUpdateAvailable error = fmt.Errorf("No update available")
	ErrUnsupportedOSArch error = fmt.Errorf("OS/Arch is not supported")
)

type Params struct {
	// protocol version
	Version int `json:"version"`
	// identifier of the application to update
	AppId string `json:"app_id"`
	// version of the application updating itself
	AppVersion string `json:"app_version"`
	// operating system of target platform
	OS string `json:"-"`
	// hardware architecture of target platform
	Arch string `json:"-"`
	// application-level user identifier
	UserId string `json:"user_id"`
	// checksum of the binary to replace (used for returning diff patches)
	Checksum string `json:"checksum"`
	// release channel (empty string means 'stable')
	Channel string `json:"-"`
	// tags for custom update channels
	Tags map[string]string `json:"tags"`
}

type Result struct {
	up *update.Update

	// should the update be applied automatically/manually
	Initiative Initiative `json:"initiative"`
	// url where to download the updated application
	Url string `json:"url"`
	// a URL to a patch to apply
	PatchUrl string `json:"patch_url"`
	// the patch format (only bsdiff supported at the moment)
	PatchType update.PatchType `json:"patch_type"`
	// version of the new application
	Version string `json:"version"`
	// expected checksum of the new application
	Checksum string `json:"checksum"`
	// signature for verifying update authenticity
	Signature string `json:"signature"`
}

var rand *mathrand.Rand

func init() {
	rand = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
}

// CheckForUpdate makes an HTTP post to a URL with the JSON serialized
// representation of Params. It returns the deserialized result object
// returned by the remote endpoint or an error. If you do not set
// OS/Arch, CheckForUpdate will populate them for you. Similarly, if
// Version is 0, it will be set to 1. Lastly, if Checksum is the empty
// string, it will be automatically be computed for the running program's
// executable file.
func (p *Params) CheckForUpdate(url string, up *update.Update) (*Result, error) {
	if p.Tags == nil {
		p.Tags = make(map[string]string)
	}

	if p.Channel == "" {
		p.Channel = "stable"
	}

	if p.OS == "" {
		p.OS = runtime.GOOS
	}

	if p.Arch == "" {
		p.Arch = runtime.GOARCH
	}

	if p.Version == 0 {
		p.Version = 1
	}

	// ignore errors auto-populating the checksum
	// if it fails, you just won't be able to patch
	if p.OS != "android" {
		if up.TargetPath == "" {
			var err error
			p.Checksum, err = defaultChecksum()
			if err != nil {
				log.Errorf("Error while trying to get default checksum: %v", err)
				return nil, err
			}
		} else {
			checksum, err := update.ChecksumForFile(up.TargetPath)
			if err != nil {
				log.Errorf("Could not get checksum: %v", err)
				return nil, err
			}
			p.Checksum = hex.EncodeToString(checksum)
		}
	}

	p.Tags["os"] = p.OS
	p.Tags["arch"] = p.Arch
	p.Tags["channel"] = p.Channel

	body, err := json.Marshal(p)
	if err != nil {
		log.Errorf("Error marshalling json for update request: %v", err)
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	frontedURL := *req.URL
	frontedURL.Host = "d2yl1zps97e5mx.cloudfront.net"
	proxied.PrepareForFronting(req, frontedURL.String())

	req.Header.Set("Content-Type", "application/json")

	nonce := rand.Int63()
	// This nonce is a random number that is going to alter the server's message
	// signature, which is sent by the server as a header and verified by the
	// client.
	req.Header.Set("X-Message-Nonce", fmt.Sprintf("%d", nonce))

	dump, dumpErr := httputil.DumpRequestOut(req, true)
	if dumpErr != nil {
		log.Errorf("Could not dump request? %v", err)
	} else {
		log.Debugf("Sending request:\n%v", string(dump))
	}

	resp, err := update.HTTPClient.Do(req)
	if err != nil {
		log.Errorf("Error submitting update request: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	dump, dumpErr = httputil.DumpResponse(resp, false)
	if err != nil {
		log.Errorf("Could not dump response? %v", err)
	} else {
		log.Debugf("Received response:\n%v", string(dump))
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue
	case http.StatusNoContent:
		return nil, ErrNoUpdateAvailable // No update available.
	case http.StatusExpectationFailed:
		return nil, ErrUnsupportedOSArch // OS/Arch is not supported.
	default:
		return nil, errors.New("Could not get a successful response from update server.")
	}

	// Reading message.
	signature, err := hex.DecodeString(resp.Header.Get("X-Message-Signature"))
	if err != nil {
		log.Errorf("No signature header found")
		return nil, err
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading response body from update server: %v", err)
		return nil, err
	}

	// Checking signature
	if err := up.ValidateMessage(respBytes, signature, nonce); err != nil {
		return nil, fmt.Errorf("Failed to validate message: %v", err)
	}

	// Working with the result
	result := &Result{up: up}
	if err := json.Unmarshal(respBytes, result); err != nil {
		log.Errorf("Error reading JSON response body from update server: %v", err)
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := &Result{up: up}
		if err := json.Unmarshal(respBytes, result); err != nil {
			log.Errorf("Error reading JSON response body from update server: %v", err)
			return nil, fmt.Errorf("json.Unmarshal: %v (text was %q)", err, string(respBytes))
		}
		return result, nil
	}

	log.Errorf("Error reading JSON response body from update server, status: %d, content: %v", resp.StatusCode, string(respBytes))
	return nil, errors.New(string(respBytes))
}

func (p *Params) CheckAndApplyUpdate(url string, up *update.Update) (result *Result, err error, errRecover error) {
	// check for an update
	result, err = p.CheckForUpdate(url, up)
	if err != nil {
		return
	}

	// run the available update
	err, errRecover = result.Update()
	return
}

func (r *Result) Update() (err error, errRecover error) {
	if r.Checksum != "" {
		r.up.Checksum, err = hex.DecodeString(r.Checksum)
		if err != nil {
			return
		}
	}

	if r.Signature != "" {
		r.up.Signature, err = hex.DecodeString(r.Signature)
		if err != nil {
			return
		}
	}

	if r.PatchType != "" {
		r.up.PatchType = r.PatchType
	}

	if r.Url == "" && r.PatchUrl == "" {
		err = fmt.Errorf("Result does not contain an update url or patch update url")
		return
	}

	if r.PatchUrl != "" {
		err, errRecover = r.up.FromUrl(r.PatchUrl)
		if err == nil {
			// success!
			return
		} else {
			// failed to update from patch URL, try with the whole thing
			if r.Url == "" || errRecover != nil {
				// we can't try updating from a URL with the full contents
				// in these cases, so fail
				return
			}
		}
	}

	// try updating from a URL with the full contents
	r.up.PatchType = update.PATCHTYPE_NONE
	return r.up.FromUrl(r.Url)
}

func defaultChecksum() (string, error) {
	path, err := osext.Executable()
	if err != nil {
		return "", err
	}

	checksum, err := update.ChecksumForFile(path)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(checksum), nil
}
