<<<<<<< HEAD
package clamd

import (
	"net"
	"net/url"
	"time"
	"fmt"
	"strings"
)

/* Variables */

//ClamD : connection object in charge of
// handling most ClamD functions
type ClamD struct {
	addr string
	url  *url.URL
}

//ClamDStats : returned statistics object after
// requesting statistics from ClamD
type ClamDStats struct {
=======
/*
Open Source Initiative OSI - The MIT License (MIT):Licensing

The MIT License (MIT)
Copyright (c) 2013 DutchCoders <http://github.com/dutchcoders/>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package clamd

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const (
	RES_OK          = "OK"
	RES_FOUND       = "FOUND"
	RES_ERROR       = "ERROR"
	RES_PARSE_ERROR = "PARSE ERROR"
)

type Clamd struct {
	address string
}

type Stats struct {
>>>>>>> b970184f4d9e88ff402581ec3dd3b9d074cfb90c
	Pools    string
	State    string
	Threads  string
	Memstats string
<<<<<<< HEAD
	Queue string
}

var (
	EICAR = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

	errNoResp = fmt.Errorf("error no response")
)

/* Functions */

//NewClamd : spawn new ClamD instance to sent commands to ClamAV-Daemon
func NewClamd(addr string) (*ClamD, error) {
	// attempt to parse addr as connection url
	url, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	// spawn ClamD
	return &ClamD{
		addr: addr,
		url: url,
	}, nil
}

//NewClamdTCP : spawn new clamd instance with default tcp address
func NewClamdTCP() (*ClamD, error) {
	return NewClamd("tcp://127.0.0.1:3310")
}

//NewClamdUnix : spawn new clamd instance with default unix address
func NewClamdUnix() (*ClamD, error) {
	return NewClamd("unix:///var/run/clamav/clamd.ctl")
}

/* Methods */

//(*ClamD).spawnConn : attempt to spawn connection to clamd
func (d *ClamD) spawnConn() (*clamdConn, error) {
	var (
		err   error
		conn  *clamdConn
		connR net.Conn
	)
	switch d.url.Scheme {
	case "tcp":  connR, err = net.DialTimeout("tcp", d.url.Host, 2 * time.Second)
	case "unix": connR, err = net.Dial("unix", d.url.Path)
	default:     connR, err = net.Dial("unix", d.addr)
	}
	if err != nil {
		return nil, err
	}
	conn = &clamdConn{connR}
	return conn, err
}

//(*ClamD).command : run a basic command and return result from clamd
func (d *ClamD) command(cmd string) ([]*Result, error) {
	// spawn connection
	conn, err := d.spawnConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// run command
	if err = conn.Command(cmd); err != nil {
		return nil, err
	}
	return conn.Responses(), err
}

//(*ClamD).commandAwait : run command and await specific expected response
func (d *ClamD) commandAwait(cmd, await string) error {
	// attempt to run basic command
	res, err := d.command(cmd)
	if err != nil {
		return err
	}
	// check output for expected response
	for _, r := range res {
		if r.raw == await {
			return nil
		}
		return fmt.Errorf("invalid response: %s", r.raw)
	}
	return errNoResp
}

//(*ClamD).Ping : attempt basic ping command to ClamD
func (d *ClamD) Ping() error {
	return d.commandAwait("PING", "PONG")
}

//(*ClamD).Reload : attempt to reload ClamD
func (d *ClamD) Reload() error {
	return d.commandAwait("RELOAD", "RELOADING")
}

//(*ClamD).Shutdown : send shutdown command to ClamD
func (d *ClamD) Shutdown() error {
	_, err := d.command("SHUTDOWN")
	return err
}

//(*ClamD).Version : return version information from clamd
func (d *ClamD) Version() (string, error) {
	out, err := d.command("VERSION")
	if err != nil {
		return "", err
	}
	if len(out) == 0 {
		return "", errNoResp
	}
	return out[0].raw, nil
}

//(*ClamD).Stats : return statistics for ClamD
func (d *ClamD) Stats() (*ClamDStats, error) {
	results, err := d.command("STATS")
	if err != nil {
		return nil, err
	}
	stats := &ClamDStats{}
	for _, r := range results {
		switch {
		case strings.HasPrefix(r.raw, "POOLS"):
			stats.Pools = r.raw[7:]
		case strings.HasPrefix(r.raw, "STATE"):
			stats.State = r.raw[7:]
		case strings.HasPrefix(r.raw, "THREADS"):
			stats.Threads = r.raw[9:]
		case strings.HasPrefix(r.raw, "QUEUE"):
			stats.Queue = r.raw[7:]
		case strings.HasPrefix(r.raw, "MEMSTATS"):
			stats.Memstats = r.raw[10:]
		case strings.HasPrefix(r.raw, "END"):
		default:
		}
	}
	return stats, nil
}

//(*ClamD).NewInStream : return stream object in charge
// of passing and collecting results from incoming bytes
func (d *ClamD) NewInStream() (*InStream, error) {
	// attempt to spawn connection
	conn, err := d.spawnConn()
	if err != nil {
		return nil, err
	}
	// attempt to start in-stream command
	if err = conn.Command("INSTREAM"); err != nil {
		conn.Close()
		return nil, err
	}
	// return stream object
	return &InStream{
		chSize: 1024,
		conn: conn,
	}, nil
}

//(*ClamD).ScanBytes : scan raw bytes and report results from ClamD
// using 'INSTREAM' command
func (d *ClamD) ScanBytes(b []byte) ([]*Result, error) {
	// check if chunk size is too big
	if len(b) > 1024 {
		return nil, fmt.Errorf("chunk size < %d bytes", 1024)
	}
	// spawn conn
	conn, err := d.spawnConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// start bytes in-stream
	if err = conn.Command("INSTREAM"); err != nil {
		return nil, err
	}
	// attempt to write chunk and return data
	if err = conn.Chunk(b); err != nil {
		return nil, err
	}
	// attempt to write EOF to end daemon reads
	if err = conn.EOF(); err != nil {
		return nil, err
	}
	return conn.Responses(), nil
}

//(*ClamD).ScanFile : Scan file or directory (recursively)
// with archive support enabled (a full path is required).
func (d *ClamD) ScanFile(path string) ([]*Result, error) {
	return d.command("SCAN "+path)
}

//(*ClamD).ScanRawFile : scan file or directory (recursively)
// with archive and special file support disabled (a full path is required).
func (d *ClamD) ScanRawFile(path string) ([]*Result, error) {
	return d.command("RAWSCAN "+path)
}


//(*ClamD).MultiScanFile : scan file in a standard way or scan directory (recursively)
// using multiple threads  (to make the scanning faster on SMP machines).
func (d *ClamD) MultiScanFile(path string) ([]*Result, error) {
	return d.command("MULTISCAN "+path)
}

//(*ClamD).ContScanFile : Scan file or directory (recursively)
// with archive support enabled and don’t stop the scanning when a virus is found.
func (d *ClamD) ContScanFile(path string) ([]*Result, error) {
	return d.command("MULTISCAN "+path)
}

//(*ClamD).ContScanFile : scan file or directory (recursively)
// with archive support enabled and don’t stop the scanning when a virus is found.
func (d *ClamD) AllMatchScanFile(path string) ([]*Result, error) {
	return d.command("MULTISCAN "+path)
}



=======
	Queue    string
}

type ScanResult struct {
	Raw         string
	Description string
	Path        string
	Hash        string
	Size        int
	Status      string
}

var EICAR = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

func (c *Clamd) newConnection() (conn *CLAMDConn, err error) {

	var u *url.URL

	if u, err = url.Parse(c.address); err != nil {
		return
	}

	switch u.Scheme {
	case "tcp":
		conn, err = newCLAMDTcpConn(u.Host)
	case "unix":
		conn, err = newCLAMDUnixConn(u.Path)
	default:
		conn, err = newCLAMDUnixConn(c.address)
	}

	return
}

func (c *Clamd) simpleCommand(command string) (chan *ScanResult, error) {
	conn, err := c.newConnection()
	if err != nil {
		return nil, err
	}

	err = conn.sendCommand(command)
	if err != nil {
		return nil, err
	}

	ch, wg, err := conn.readResponse()

	go func() {
		wg.Wait()
		conn.Close()
	}()

	return ch, err
}

/*
Check the daemon's state (should reply with PONG).
*/
func (c *Clamd) Ping() error {
	ch, err := c.simpleCommand("PING")
	if err != nil {
		return err
	}

	select {
	case s := (<-ch):
		switch s.Raw {
		case "PONG":
			return nil
		default:
			return errors.New(fmt.Sprintf("Invalid response, got %s.", s))
		}
	}

	return nil
}

/*
Print program and database versions.
*/
func (c *Clamd) Version() (chan *ScanResult, error) {
	dataArrays, err := c.simpleCommand("VERSION")
	return dataArrays, err
}

/*
On this command clamd provides statistics about the scan queue, contents of scan
queue, and memory usage. The exact reply format is subject to changes in future
releases.
*/
func (c *Clamd) Stats() (*Stats, error) {
	ch, err := c.simpleCommand("STATS")
	if err != nil {
		return nil, err
	}

	stats := &Stats{}

	for s := range ch {
		if strings.HasPrefix(s.Raw, "POOLS") {
			stats.Pools = strings.Trim(s.Raw[6:], " ")
		} else if strings.HasPrefix(s.Raw, "STATE") {
			stats.State = s.Raw
		} else if strings.HasPrefix(s.Raw, "THREADS") {
			stats.Threads = s.Raw
		} else if strings.HasPrefix(s.Raw, "QUEUE") {
			stats.Queue = s.Raw
		} else if strings.HasPrefix(s.Raw, "MEMSTATS") {
			stats.Memstats = s.Raw
		} else if strings.HasPrefix(s.Raw, "END") {
		} else {
			//	return nil, errors.New(fmt.Sprintf("Unknown response, got %s.", s))
		}
	}

	return stats, nil
}

/*
Reload the databases.
*/
func (c *Clamd) Reload() error {
	ch, err := c.simpleCommand("RELOAD")
	if err != nil {
		return err
	}

	select {
	case s := (<-ch):
		switch s.Raw {
		case "RELOADING":
			return nil
		default:
			return errors.New(fmt.Sprintf("Invalid response, got %s.", s))
		}
	}

	return nil
}

func (c *Clamd) Shutdown() error {
	_, err := c.simpleCommand("SHUTDOWN")
	if err != nil {
		return err
	}

	return err
}

/*
Scan file or directory (recursively) with archive support enabled (a full path is
required).
*/
func (c *Clamd) ScanFile(path string) (chan *ScanResult, error) {
	command := fmt.Sprintf("SCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file or directory (recursively) with archive and special file support disabled
(a full path is required).
*/
func (c *Clamd) RawScanFile(path string) (chan *ScanResult, error) {
	command := fmt.Sprintf("RAWSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file in a standard way or scan directory (recursively) using multiple threads
(to make the scanning faster on SMP machines).
*/
func (c *Clamd) MultiScanFile(path string) (chan *ScanResult, error) {
	command := fmt.Sprintf("MULTISCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file or directory (recursively) with archive support enabled and don’t stop
the scanning when a virus is found.
*/
func (c *Clamd) ContScanFile(path string) (chan *ScanResult, error) {
	command := fmt.Sprintf("CONTSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file or directory (recursively) with archive support enabled and don’t stop
the scanning when a virus is found.
*/
func (c *Clamd) AllMatchScanFile(path string) (chan *ScanResult, error) {
	command := fmt.Sprintf("ALLMATCHSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan a stream of data. The stream is sent to clamd in chunks, after INSTREAM,
on the same socket on which the command was sent. This avoids the overhead
of establishing new TCP connections and problems with NAT. The format of the
chunk is: <length><data> where <length> is the size of the following data in
bytes expressed as a 4 byte unsigned integer in network byte order and <data> is
the actual chunk. Streaming is terminated by sending a zero-length chunk. Note:
do not exceed StreamMaxLength as defined in clamd.conf, otherwise clamd will
reply with INSTREAM size limit exceeded and close the connection
*/
func (c *Clamd) ScanStream(r io.Reader, abort chan bool) (chan *ScanResult, error) {
	conn, err := c.newConnection()
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			_, allowRunning := <-abort
			if !allowRunning {
				break
			}
		}
		conn.Close()
	}()

	conn.sendCommand("INSTREAM")

	for {
		buf := make([]byte, CHUNK_SIZE)

		nr, err := r.Read(buf)
		if nr > 0 {
			conn.sendChunk(buf[0:nr])
		}

		if err != nil {
			break
		}

	}

	err = conn.sendEOF()
	if err != nil {
		return nil, err
	}

	ch, wg, err := conn.readResponse()

	go func() {
		wg.Wait()
		conn.Close()
	}()

	return ch, nil
}

func NewClamd(address string) *Clamd {
	clamd := &Clamd{address: address}
	return clamd
}
>>>>>>> b970184f4d9e88ff402581ec3dd3b9d074cfb90c
