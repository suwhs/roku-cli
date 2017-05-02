package commands

import (
    "time"
    "archive/zip"
    "errors"
    "bytes"
    "crypto/md5"
    "encoding/hex"
    "fmt"
    "io"
    "io/ioutil"
    "mime/multipart"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "regexp"
    "gopkg.in/urfave/cli.v1"
    "github.com/oddnetworks/roku-cli/rc"
)

var requiredPaths []string = []string{"manifest", "source"}
var allowedPaths []string = []string{"manifest", "source", "images", "components", "fonts", "assets" }

type authorization struct {
    Username, Password, Realm, NONCE, QOP, Opaque, Algorithm string
}

func (as *authorization) digest(method string, url string) (string, error) {
    config, _ := rc.LoadRC()
    device := config.CurrentDevice()
    login := strings.Join([]string{as.Username, as.Realm, as.Password}, ":")
    h := md5.New()
    io.WriteString(h, login)
    loginHash := hex.EncodeToString(h.Sum(nil))
    if method!="GET" && method!="POST" {
        return "", errors.New("only GET and POST methods supported")
    }
    auth := &authorization{"rokudev", device.Password, "rokudev", "", "auth", "", ""}
    action := strings.Join([]string{method, url}, ":")
    h = md5.New()
    io.WriteString(h, action)
    actionHash := hex.EncodeToString(h.Sum(nil))

    nc_str := fmt.Sprintf("%08x", 3)
    hnc := "MTM3MDgw"

    responseDigest := fmt.Sprintf("%s:%s:%s:%s:%s:%s", loginHash, as.NONCE, nc_str, hnc, as.QOP, actionHash)
    h = md5.New()
    io.WriteString(h, responseDigest)
    responseDigest = hex.EncodeToString(h.Sum(nil))

    digest := "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\""
    digest = fmt.Sprintf(digest, as.Username, as.Realm, as.NONCE, url, responseDigest)
    if auth.Opaque != "" {
        digest += fmt.Sprintf(", opaque=\"%s\"", as.Opaque)
    }
    if auth.QOP != "" {
        digest += fmt.Sprintf(", qop=\"%s\", nc=%s, cnonce=\"%s\"", as.QOP, nc_str, hnc)
    }
    if auth.Algorithm != "" {
        digest += fmt.Sprintf(", algorithm=\"%s\"", as.Algorithm)
    }
    return digest, nil
}


func EnsurePaths(c *cli.Context) error {
    if FS.Source == "" {
        FS.Source = "./"
    }

    // Verify source folder contains required Roku files and folders
    for _, required := range requiredPaths {
        verifyPath := filepath.Join(FS.Source, required)
        if _, err := os.Stat(verifyPath); os.IsNotExist(err) {
            return cli.NewExitError("Not a valid Roku project. Missing: "+verifyPath, 1)
        }
    }

    fmt.Println("Building from path:", FS.Source)

    if FS.Destination == "" {
        FS.Destination = filepath.Join(FS.Source, "build")
    }

    // Make the destination folder if it doesn't exist
    if _, err := os.Stat(FS.Destination); os.IsNotExist(err) {
        err = os.Mkdir(FS.Destination, os.ModePerm)
    }

    if FS.Zip == "" {
        FS.Zip = filepath.Join(FS.Destination, "channel.zip")
    } else {
        FS.Zip = filepath.Join(FS.Destination, FS.Zip)
    }

    return nil
}

// return True if any file in FS.Source modification time > destination zip file modification time

func IsSourceChanges() bool {
    return false
}

func ZipContainsAll() bool {
    return false
}

func Build(c *cli.Context) error {
    // TODO:
    if !IsSourceChanges() && ZipContainsAll() {
        fmt.Println("Build: source not changes")
        return nil
    }
    // Make a new file handler and zip archive
    zipFile, err := os.Create(FS.Zip)
    if err != nil {
        return cli.NewExitError("Zip file could not be created: "+err.Error(), 1)
    }
    defer zipFile.Close()

    archive := zip.NewWriter(zipFile)
    defer archive.Close()

    // Walk the source path and add each path to the archive

    roots, err := ioutil.ReadDir(FS.Source)

    // fmt.Printf("roots: %+v\n", roots)
    for _, r := range roots {
        for _, allowed := range allowedPaths {
            if strings.Contains(r.Name(), allowed) {
                err = filepath.Walk(filepath.Join(FS.Source, r.Name()), func(path string, info os.FileInfo, err error) error {
                    if err != nil {
                        return err
                    }

                    for _, allowed := range allowedPaths {
                        if strings.Contains(path, allowed) {
                            header, err := zip.FileInfoHeader(info)
                            if err != nil {
                                return err
                            }
                            // fmt.Printf("compress %s [%+v]\n", path, allowedPaths)
                            header.Name = strings.TrimPrefix(path, FS.Source+"/")

                            header.Method = zip.Store
                            if info.IsDir() {
                                header.Name += "/"
                            } else {
                                header.Method = zip.Deflate
                            }

                            writer, err := archive.CreateHeader(header)
                            if err != nil {
                                return err
                            }

                            if info.IsDir() {
                                return nil
                            }

                            file, err := os.Open(path)
                            if err != nil {
                                return err
                            }
                            defer file.Close()

                            _, err = io.Copy(writer, file)
                            return err
                        }
                    }

                    return err
                })
            }
        }
    }
    if err != nil {
        return cli.NewExitError("Error zipping: "+err.Error(), 1)
    }

    fmt.Println("Build complete:", FS.Zip)

    return nil
}

func Install(c *cli.Context) error {
    err := Build(c)
    if err != nil {
        return err
    }

    // Open the rc file and get the current device
    config, _ := rc.LoadRC()
    device := config.CurrentDevice()

    // Open the zip file
    zip, err := os.Open(FS.Zip)
    if err != nil {
        return cli.NewExitError("Error reading zip file: "+err.Error(), 1)
    }
    defer zip.Close()

    // Build a form and add the zip binary file
    form := &bytes.Buffer{}
    writer := multipart.NewWriter(form)
    part, err := writer.CreateFormFile("archive", filepath.Base(FS.Zip))
    if err != nil {
        return cli.NewExitError("Error attaching zip file: "+err.Error(), 1)
    }
    _, err = io.Copy(part, zip)

    writer.WriteField("mysubmit", "Install")
    writer.Close()

    // Simple auth struct
    auth := &authorization{"rokudev", device.Password, "rokudev", "", "auth", "", ""}

    // Begin building HTTP Digest Auth
    login := strings.Join([]string{auth.Username, auth.Realm, auth.Password}, ":")
    h := md5.New()
    io.WriteString(h, login)
    loginHash := hex.EncodeToString(h.Sum(nil))

    action := strings.Join([]string{"POST", "/plugin_install"}, ":")
    h = md5.New()
    io.WriteString(h, action)
    actionHash := hex.EncodeToString(h.Sum(nil))

    nc_str := fmt.Sprintf("%08x", 3)
    hnc := "MTM3MDgw"

    responseDigest := fmt.Sprintf("%s:%s:%s:%s:%s:%s", loginHash, auth.NONCE, nc_str, hnc, auth.QOP, actionHash)
    h = md5.New()
    io.WriteString(h, responseDigest)
    responseDigest = hex.EncodeToString(h.Sum(nil))

    digest := "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\""
    digest = fmt.Sprintf(digest, auth.Username, auth.Realm, auth.NONCE, "/plugin_install", responseDigest)
    if auth.Opaque != "" {
        digest += fmt.Sprintf(", opaque=\"%s\"", auth.Opaque)
    }
    if auth.QOP != "" {
        digest += fmt.Sprintf(", qop=\"%s\", nc=%s, cnonce=\"%s\"", auth.QOP, nc_str, hnc)
    }
    if auth.Algorithm != "" {
        digest += fmt.Sprintf(", algorithm=\"%s\"", auth.Algorithm)
    }

    req, err := http.NewRequest("POST", "http://"+device.IP+"/plugin_install", form)
    req.Header.Set("Content-Type", writer.FormDataContentType())
    req.Header.Set("Authorization", "Digest "+digest)

    client := &http.Client{}
    res, err := client.Do(req)
    if err != nil {
        return cli.NewExitError("Error installing build: "+err.Error(), 1)
    } else {
        if res.StatusCode == 401 {
            return cli.NewExitError("Error installing build: Username/Password incorrect for "+device.IP, 1)
        }

        // Parse the HTML for the Roku message
        resBody, _ := ioutil.ReadAll(res.Body)
        body := string(resBody)
        messageIndex := strings.Index(body, "Roku.Message")
        scriptIndex := strings.LastIndex(body, "Render")
        message := body[messageIndex+15 : scriptIndex-10]
        triggers := strings.Split(message, ".")
        content := strings.Split(triggers[1], "', '")
        fmt.Println("Install complete:", device.Name, device.IP)
        fmt.Println("Roku Response:", "\""+content[1]+"\"")
    }

    return nil
}

func Package(c *cli.Context) error {

    err := Build(c)
    if err != nil {
        return err
    }

    // Open the rc file and get the current device
    config, _ := rc.LoadRC()
    device := config.CurrentDevice()

    // Open the zip file
    zip, err := os.Open(FS.Destination)
    if err != nil {
        return cli.NewExitError("Error reading zip file: "+err.Error(), 1)
    }
    defer zip.Close()

    // Build a form and add the zip binary file
    form := &bytes.Buffer{}
    writer := multipart.NewWriter(form)
  //  'part, err := writer.CreateFormFile("archive", filepath.Base(FS.Zip))
  //  'if err != nil {
  //  '    return cli.NewExitError("Error attaching zip file: "+err.Error(), 1)
  //  '}
  //  '_, err = io.Copy(part, zip)

    writer.WriteField("mysubmit", "Package")
    writer.WriteField("pkg_time", fmt.Sprintf("%d",int32(time.Now().Unix())))
    writer.WriteField("app_name", FS.AppName)
    writer.WriteField("passwd", FS.Sign)
    writer.Close()

    // Simple auth struct
    auth := &authorization{"rokudev", device.Password, "rokudev", "", "auth", "", ""}

    // Begin building HTTP Digest Auth
    login := strings.Join([]string{auth.Username, auth.Realm, auth.Password}, ":")
    h := md5.New()
    io.WriteString(h, login)
    loginHash := hex.EncodeToString(h.Sum(nil))

    action := strings.Join([]string{"POST", "/plugin_package"}, ":")
    h = md5.New()
    io.WriteString(h, action)
    actionHash := hex.EncodeToString(h.Sum(nil))

    nc_str := fmt.Sprintf("%08x", 3)
    hnc := "MTM3MDgw"

    responseDigest := fmt.Sprintf("%s:%s:%s:%s:%s:%s", loginHash, auth.NONCE, nc_str, hnc, auth.QOP, actionHash)
    h = md5.New()
    io.WriteString(h, responseDigest)
    responseDigest = hex.EncodeToString(h.Sum(nil))

    digest := "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\""
    digest = fmt.Sprintf(digest, auth.Username, auth.Realm, auth.NONCE, "/plugin_package", responseDigest)
    if auth.Opaque != "" {
        digest += fmt.Sprintf(", opaque=\"%s\"", auth.Opaque)
    }
    if auth.QOP != "" {
        digest += fmt.Sprintf(", qop=\"%s\", nc=%s, cnonce=\"%s\"", auth.QOP, nc_str, hnc)
    }
    if auth.Algorithm != "" {
        digest += fmt.Sprintf(", algorithm=\"%s\"", auth.Algorithm)
    }
    // fmt.Printf("working auth: '%s'\n",digest)
    // Post the form with the digest auth to the Roku device
    req, err := http.NewRequest("POST", "http://"+device.IP+"/plugin_package", form)
    req.Header.Set("Content-Type", writer.FormDataContentType())
    req.Header.Set("Authorization", "Digest "+digest)
    //fmt.Printf("stage: requesting: (%s)\n",digest)
    client := DefaultTimeoutClient() // &http.Client{}
    res, err := client.Do(req)
    //fmt.Println("stage: process response\n")
    if err != nil {
        return cli.NewExitError("Error packaging build: "+err.Error(), 1)
    } else {
        if res.StatusCode == 401 {
            return cli.NewExitError("Error packageing build: Username/Password incorrect for "+device.IP, 1)
        }
        // fmt.Println("stage: read")
        // Parse the HTML for the Roku message
        resBody, _ := ioutil.ReadAll(res.Body)
        _, packaged, err := ExtractAppIdAndPackage(resBody)
        if err != nil {
            fmt.Printf("error: %+v\n", err)
        } else {
            packaged = fmt.Sprintf("http://"+device.IP+"/%s", packaged)
            // fmt.Printf("packaged url: %s\n",packaged)
        }
        body := string(resBody)
        messageIndex := strings.Index(body, "Roku.Message")
        scriptIndex := strings.LastIndex(body, "Render")
        message := body[messageIndex+15 : scriptIndex-10]
        triggers := strings.Split(message, ".")
        content := strings.Split(triggers[1], "', '")
        fmt.Println("Package complete:", device.Name, device.IP)
        fmt.Println("Roku Response:", "\""+content[1]+"\"")
        if packaged!="" {
            return Download(c,packaged)
        }
    }

    return nil
}

func Download(c *cli.Context, url string) error {
    // Open the rc file and get the current device
    config, _ := rc.LoadRC()
    device := config.CurrentDevice()

    // Simple auth struct
    auth := &authorization{"rokudev", device.Password, "rokudev", "", "auth", "", ""}

    // Begin building HTTP Digest Auth
    login := strings.Join([]string{auth.Username, auth.Realm, auth.Password}, ":")
    h := md5.New()
    io.WriteString(h, login)
    loginHash := hex.EncodeToString(h.Sum(nil))

    action := strings.Join([]string{"GET", url}, ":")
    h = md5.New()
    io.WriteString(h, action)
    actionHash := hex.EncodeToString(h.Sum(nil))

    nc_str := fmt.Sprintf("%08x", 3)
    hnc := "MTM3MDgw"

    responseDigest := fmt.Sprintf("%s:%s:%s:%s:%s:%s", loginHash, auth.NONCE, nc_str, hnc, auth.QOP, actionHash)
    h = md5.New()
    io.WriteString(h, responseDigest)
    responseDigest = hex.EncodeToString(h.Sum(nil))

    digest := "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\""
    digest = fmt.Sprintf(digest, auth.Username, auth.Realm, auth.NONCE, url, responseDigest)
    if auth.Opaque != "" {
        digest += fmt.Sprintf(", opaque=\"%s\"", auth.Opaque)
    }
    if auth.QOP != "" {
        digest += fmt.Sprintf(", qop=\"%s\", nc=%s, cnonce=\"%s\"", auth.QOP, nc_str, hnc)
    }
    if auth.Algorithm != "" {
        digest += fmt.Sprintf(", algorithm=\"%s\"", auth.Algorithm)
    }

    // -- end authorization_struct digest --
    // fmt.Printf("working auth: '%s'\n",digest)
    // Post the form with the digest auth to the Roku device
    // fullUrl := "http://"+device.IP+"/" + url
    // fmt.Printf("full url:'%s'\n", fullUrl)
    req, err := http.NewRequest("GET", url, nil)
    // req.Header.Set("Content-Type", writer.FormDataContentType())
    req.Header.Set("Authorization", "Digest "+digest)
    // fmt.Printf("stage: requesting: (%s)\n",digest)
    client := DefaultTimeoutClient() // &http.Client{}
    res, err := client.Do(req)
    // fmt.Println("stage: process response\n")
    if err != nil {
        return cli.NewExitError("Error downloading build: "+err.Error(), 1)
    } else {
        if res.StatusCode == 401 {
            return cli.NewExitError("Error downloading build: Username/Password incorrect for "+device.IP, 1)
        }
        // fmt.Println("stage: read")
        // Parse the HTML for the Roku message
        resBody, _ := ioutil.ReadAll(res.Body)
        outName := filepath.Base(url)
        outDir := filepath.Dir(FS.Destination)
        fmt.Printf("write file: %s to %s [%d bytes]\n",outName,outDir,len(resBody))
        outPathName := fmt.Sprintf("%s/%s",outDir,outName)
        ioutil.WriteFile(outPathName,resBody,0644)
        fmt.Println("Sign complete:", outPathName)
        // fmt.Println("Roku Response:", "\""+content[1]+"\"")
    }

    return nil
}

func ExtractAppIdAndPackage(html []byte) (string,string,error) {
    // extract current package name
    // <label>Your Dev ID: &nbsp;</label> b2cd827d75cd1361811fb1f2e43c3d3f84d260cc</label><hr />
    devIdRx := regexp.MustCompile("Your Dev ID:.*</label>\\s*(\\S+)</label>")
    // <label>Currently Installed Application:</label><div><font face="Courier">8b55278a6e6b09f3a3ce4e6cb05581c0 <br /> zip file in internal memory (590048 bytes)</font></div><hr />
    // appRx := regexp.MustCompile("Currently Installed Application:</label>.*>([^<^>]\\S+)\\s*<br")
    // <label>Currently Packaged Application:</label><div><font face="Courier"><a href="pkgs//Pc6ee4ea70e27155f799e1648117eb807.pkg">Pc6ee4ea70e27155f799e1648117eb807.pkg</a> <br> package file (590048 bytes)</font></div>
    pkgRx := regexp.MustCompile("Currently Packaged Application:</label>.*<a href=\"(pkgs//\\S+.pkg)\">([^<^>]\\S+)\\s*</a")

    deviceId := ""
    // application := ""
    pkgUrl := ""

    // fmt.Printf("BODY:\n%s\nEND BODY\n", string(html))
    if devIdRx.Match(html) {
        strs := devIdRx.FindAllStringSubmatch(string(html),-1)
        for pair := range strs {
            deviceId = strs[pair][1]
            // fmt.Printf("dev: %+v\n",strs[pair])
        }
    }

    // if appRx.Match(html) {
        //strs := appRx.FindAllStringSubmatch(string(html),-1)
        //for pair := range strs {
            // fmt.Printf("app: %+v\n",strs[pair])
        //}
    // }

    if pkgRx.Match(html) {
        strs := pkgRx.FindAllStringSubmatch(string(html),-1)
        for pair := range strs {
            // fmt.Printf("pkg: %+v\n",strs[pair])
            pkgUrl = strs[pair][1]
        }
    }
    return deviceId, pkgUrl, nil
}
