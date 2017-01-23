// Decompiled with JetBrains decompiler
// Type: VirusTotalNET.VirusTotal
// Assembly: VirusTotal.NET, Version=1.3.1.0, Culture=neutral, PublicKeyToken=null
// MVID: 2B160AD8-F9AD-46F3-A2B1-F9B9E38BD041
// Assembly location: D:\repository\repo\vs2015\Security\FIDO.Threatfeeds\FIDO.Threatfeeds\packages\VirusTotal.NET.1.3.1.0\lib\VirusTotal.NET.dll

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET;
using RestSharp;
using RestSharp.Deserializers;

namespace FIDO.Threatfeeds.FIDO.Support.Threat.Feeds
{
  public class VirusTotal
  {
    private readonly RestClient _client = new RestClient();
    private readonly string _apiKey;
    private bool _useTls;

    /// <summary>
    /// When true, we check the file size before uploading it to Virus Total. The file size restrictions are based on the Virusl Total public API 2.0 documentation.
    /// </summary>
    public bool RestrictSizeLimits { get; set; }

    /// <summary>
    /// When true, we check the number of resources that are submitted to Virus Total. The limits are according to Virus Total public API 2.0 documentation.
    /// </summary>
    public bool RestrictNumberOfResources { get; set; }

    /// <summary>
    /// The maximum file size (in bytes) that the Virus Total public API 2.0 supports.
    /// </summary>
    public long FileSizeLimit { get; set; }

    /// <summary>
    /// Set to false to use HTTP instead of HTTPS. HTTPS is used by default.
    /// </summary>
    public bool UseTLS
    {
      get
      {
        return this._useTls;
      }
      set
      {
        this._useTls = value;
        string str = this.ApiUrl;
        if (string.IsNullOrWhiteSpace(str))
          return;
        if (str.StartsWith("https://", StringComparison.InvariantCultureIgnoreCase))
          str = str.Substring(8);
        else if (str.StartsWith("http://", StringComparison.InvariantCultureIgnoreCase))
          str = str.Substring(7);
        this._client.BaseUrl = this._useTls ? new Uri("https://" + str) : new Uri("http://" + str);
      }
    }

    /// <summary>Get or set the proxy.</summary>
    public IWebProxy Proxy
    {
      get
      {
        return this._client.Proxy;
      }
      set
      {
        this._client.Proxy = value;
      }
    }

    /// <summary>Get or set the timeout in miliseconds.</summary>
    public int Timeout
    {
      get
      {
        return this._client.Timeout;
      }
      set
      {
        this._client.Timeout = value;
      }
    }

    /// <summary>
    /// The URL which the Virus Total service listens on. IF you don't set the scheme to http:// or https:// it will default to https.
    /// </summary>
    public string ApiUrl
    {
      get
      {
        return this._client.BaseUrl.ToString();
      }
      set
      {
        string str = value.Trim();
        if (string.IsNullOrWhiteSpace(str))
          return;
        if (str.StartsWith("https://", StringComparison.InvariantCultureIgnoreCase))
        {
          this._useTls = true;
          str = str.Substring(8);
        }
        else if (str.StartsWith("http://", StringComparison.InvariantCultureIgnoreCase))
        {
          this._useTls = false;
          str = str.Substring(7);
        }
        else
          this._useTls = true;
        this._client.BaseUrl = this._useTls ? new Uri("https://" + str) : new Uri("http://" + str);
      }
    }

    /// <summary>Public constructor for VirusTotal.</summary>
    /// <param name="apiKey">The API key you got from Virus Total</param>
    /// <exception cref="T:System.ArgumentException"></exception>
    public VirusTotal(string apiKey)
    {
      if (string.IsNullOrEmpty(apiKey) || apiKey.Length < 64)
        throw new ArgumentException("You have to set an API key.", "apiKey");
      this.ApiUrl = "www.virustotal.com/vtapi/v2/";
      this._useTls = true;
      this._apiKey = apiKey;
      this._client.FollowRedirects = false;
      this.FileSizeLimit = 33553369L;
      this.RestrictSizeLimits = true;
      this.RestrictNumberOfResources = true;
    }

    /// <summary>
    /// Scan a file.
    /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
    /// </summary>
    /// <param name="file">The file to scan</param>
    /// <returns>The scan results.</returns>
    public ScanResult ScanFile(FileInfo file)
    {
      if (!file.Exists)
        throw new FileNotFoundException("The file was not found.", file.Name);
      using (FileStream fileStream = file.OpenRead())
        return this.ScanFile((Stream) fileStream, file.Name);
    }

    /// <summary>
    /// Scan a file.
    /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
    /// Note: Ýou are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
    /// </summary>
    /// <param name="file">The file to scan</param>
    /// <param name="filename">The filename of the file</param>
    /// <returns>The scan results.</returns>
    public ScanResult ScanFile(byte[] file, string filename)
    {
      using (MemoryStream memoryStream = new MemoryStream(file))
        return this.ScanFile((Stream) memoryStream, filename);
    }

    /// <summary>
    /// Scan a file.
    /// Note: It is highly encouraged to get the report of the file before scanning, in case it has already been scanned before.
    /// Note: Ýou are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
    /// </summary>
    /// <param name="fileStream">The file to scan</param>
    /// <param name="filename">The filename of the file</param>
    /// <returns>The scan results.</returns>
    public ScanResult ScanFile(Stream fileStream, string filename)
    {
      if (fileStream == null || fileStream.Length <= 0L)
        throw new ArgumentException("You must provide a file", "fileStream");
      if (this.RestrictSizeLimits && fileStream.Length > this.FileSizeLimit)
        throw new SizeLimitException(string.Format("The filesize limit on VirusTotal is {0} KB. Your file is {1} KB", (object) (this.FileSizeLimit / 1024L), (object) (fileStream.Length / 1024L)));
      if (string.IsNullOrWhiteSpace(filename))
        throw new ArgumentException("You must provide a filename. Preferably the original filename.");
      RestRequest request = this.PrepareRequest("file/scan", Method.POST);
      request.AddFile("file", new Action<Stream>(fileStream.CopyTo), filename, (string) null);
      return this.GetResults<ScanResult>(request);
    }

    /// <summary>
    /// Scan multiple files.
    /// Note: It is highly encouraged to get the report of the files before scanning, in case it they already been scanned before.
    /// Note: Ýou are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
    /// </summary>
    /// <param name="files">The files you wish to scan. They are a tuple of file content and filename.</param>
    /// <returns>The scan results.</returns>
    public IEnumerable<ScanResult> ScanFiles(IEnumerable<Tuple<byte[], string>> files)
    {
      foreach (Tuple<byte[], string> file in files)
      {
        MemoryStream stream = new MemoryStream(file.Item1);
        try
        {
          yield return this.ScanFile((Stream) stream, file.Item2);
        }
        finally
        {
          if (stream != null)
            stream.Dispose();
        }
        stream = (MemoryStream) null;
      }
    }

    /// <summary>
    /// Scan multiple files.
    /// Note: It is highly encouraged to get the report of the files before scanning, in case it they already been scanned before.
    /// Note: Ýou are also strongly encouraged to provide the filename as it is rich metadata for the Virus Total database.
    /// </summary>
    /// <param name="streams">The streams you wish to scan. They are a tuple of stream and filename.</param>
    /// <returns>The scan results.</returns>
    public IEnumerable<ScanResult> ScanFiles(IEnumerable<Tuple<Stream, string>> streams)
    {
      foreach (Tuple<Stream, string> stream in streams)
        yield return this.ScanFile(stream.Item1, stream.Item2);
    }

    /// <summary>
    /// Scan multiple files.
    /// Note: It is highly encouraged to get the report of the files before scanning, in case it they already been scanned before.
    /// </summary>
    /// <param name="files">The files you wish to scan.</param>
    /// <returns>The scan results.</returns>
    public IEnumerable<ScanResult> ScanFiles(IEnumerable<FileInfo> files)
    {
      foreach (FileInfo file in files)
        yield return this.ScanFile(file);
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
    /// Note: Before requesting a rescan you should retrieve the latest report on the file.
    /// </summary>
    /// <param name="resource">A hash of the file. It can be an MD5, SHA1 or SHA256</param>
    /// <returns>The scan results.</returns>
    public ScanResult RescanFile(string resource)
    {
      return this.RescanFiles((IEnumerable<string>) new string[1]{ resource }).FirstOrDefault<ScanResult>();
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
    /// Note: Before requesting a rescan you should retrieve the latest report on the file.
    /// </summary>
    /// <returns>The scan results.</returns>
    public ScanResult RescanFile(FileInfo file)
    {
      return this.RescanFiles((IEnumerable<FileInfo>) new FileInfo[1]{ file }).FirstOrDefault<ScanResult>();
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file without sending the actual file to VirusTotal.
    /// Note: Before requesting a rescan you should retrieve the latest report on the file.
    /// </summary>
    /// <returns>The scan results.</returns>
    public ScanResult RescanFile(byte[] file)
    {
      return this.RescanFiles((IEnumerable<byte[]>) new byte[1][]{ file }).FirstOrDefault<ScanResult>();
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// Note: Before requesting a rescan you should retrieve the latest report on the files.
    /// </summary>
    /// <returns>The scan results.</returns>
    public List<ScanResult> RescanFiles(IEnumerable<byte[]> files)
    {
      return this.RescanFiles(this.GetResourcesFromFiles(files));
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// Note: Before requesting a rescan you should retrieve the latest report on the files.
    /// </summary>
    /// <returns>The scan results.</returns>
    public List<ScanResult> RescanFiles(IEnumerable<FileInfo> files)
    {
      return this.RescanFiles(this.GetResourcesFromFiles(files));
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file.
    /// Note: This does not send the content of the streams to VirusTotal. It hashes the content and sends that instead.
    /// Note: Before requesting a rescan you should retrieve the latest report on the files.
    /// </summary>
    /// <returns>The scan results.</returns>
    public List<ScanResult> RescanFiles(IEnumerable<Stream> streams)
    {
      return this.RescanFiles(this.GetResourcesFromFiles(streams));
    }

    /// <summary>
    /// Tell VirusTotal to rescan a file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// Note: Before requesting a rescan you should retrieve the latest report on the files.
    /// Note: You can use MD5, SHA1 or SHA256 and even mix them.
    /// Note: You can only request a maximum of 25 rescans.
    /// </summary>
    /// <param name="resourceList">a MD5, SHA1 or SHA256 of the files. You can also specify list made up of a combination of any of the three allowed hashes (up to 25 items), this allows you to perform a batch request with one single call.
    /// Note: that the files must already be present in the files store.
    /// </param>
    /// <returns>The scan results.</returns>
    public List<ScanResult> RescanFiles(IEnumerable<string> resourceList)
    {
      string[] strArray = resourceList as string[] ?? resourceList.ToArray<string>();
      if (!((IEnumerable<string>) strArray).Any<string>())
        throw new ArgumentException("You have to supply a resource.", "resourceList");
      if (this.RestrictNumberOfResources && strArray.Length > 25)
        throw new ResourceLimitException("Too many hashes. There is a maximum of 25 hashes.");
      for (int index = 0; index < strArray.Length; ++index)
        this.ValidateResource(strArray[index]);
      RestRequest request = this.PrepareRequest("file/rescan", Method.POST);
      request.AddParameter("resource", (object) string.Join(",", strArray));
      return this.GetResults<List<ScanResult>>(request);
    }

    /// <summary>
    /// Gets the report of the file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// </summary>
    /// <param name="file">The file you wish to get a report on.</param>
    public FileReport GetFileReport(byte[] file)
    {
      return this.GetFileReport(HashHelper.GetSHA256(file));
    }

    /// <summary>
    /// Gets the report of the file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// </summary>
    /// <param name="file">The file you wish to get a report on.</param>
    public FileReport GetFileReport(FileInfo file)
    {
      return this.GetFileReport(HashHelper.GetSHA256(file));
    }

    /// <summary>
    /// Gets the report of the file.
    /// Note: This does not send the files to VirusTotal. It hashes the file and sends that instead.
    /// </summary>
    /// <param name="resource">The resource (MD5, SHA1 or SHA256) you wish to get a report on.</param>
    public FileReport GetFileReport(string resource)
    {
      return this.GetFileReports((IEnumerable<string>) new string[1]{ resource }).First<FileReport>();
    }

    /// <summary>
    /// Gets a list of reports of the files.
    /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
    /// </summary>
    /// <param name="files">The files you wish to get reports on.</param>
    public List<FileReport> GetFileReports(IEnumerable<byte[]> files)
    {
      return this.GetFileReports(this.GetResourcesFromFiles(files));
    }

    /// <summary>
    /// Gets a list of reports of the files.
    /// Note: This does not send the files to VirusTotal. It hashes the files and sends them instead.
    /// </summary>
    /// <param name="files">The files you wish to get reports on.</param>
    public List<FileReport> GetFileReports(IEnumerable<FileInfo> files)
    {
      return this.GetFileReports(this.GetResourcesFromFiles(files));
    }

    /// <summary>
    /// Gets a list of reports of the files.
    /// Note: This does not send the content of the streams to VirusTotal. It hashes the content of the stream and sends that instead.
    /// </summary>
    /// <param name="streams">The streams you wish to get reports on.</param>
    public List<FileReport> GetFileReports(IEnumerable<Stream> streams)
    {
      return this.GetFileReports(this.GetResourcesFromFiles(streams));
    }

    /// <summary>
    /// Gets the report of the file represented by its hash or scan ID.
    /// Keep in mind that URLs sent using the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours before the file is scanned,
    /// so query the report at regular intervals until the result shows up and do not keep submitting the file over and over again.
    /// </summary>
    /// <param name="resourceList">SHA1, MD5 or SHA256 of the file. It can also be a scan ID of a previous scan.</param>
    /// <returns></returns>
    public List<FileReport> GetFileReports(IEnumerable<string> resourceList)
    {
      string[] strArray = resourceList as string[] ?? resourceList.ToArray<string>();
      if (!((IEnumerable<string>) strArray).Any<string>())
        throw new ArgumentException("You have to supply a resource.", "resourceList");
      for (int index = 0; index < strArray.Length; ++index)
        this.ValidateResource(strArray[index]);
      RestRequest request = this.PrepareRequest("file/report", Method.POST);
      request.AddParameter("resource", (object) string.Join(",", strArray));
      return this.GetResults<List<FileReport>>(request);
    }

    /// <summary>
    /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
    /// Note: Before performing your submission, you should retrieve the latest report on the URL.
    /// </summary>
    /// <param name="url">The url to process.</param>
    /// <returns>The scan results.</returns>
    public ScanResult ScanUrl(string url)
    {
      return this.ScanUrls(this.UrlToUri((IEnumerable<string>) new string[1]{ url })).FirstOrDefault<ScanResult>();
    }

    /// <summary>
    /// Scan the given URL. The URL will be downloaded by VirusTotal and processed.
    /// Note: Before performing your submission, you should retrieve the latest report on the URL.
    /// </summary>
    /// <param name="url">The url to process.</param>
    /// <returns>The scan results.</returns>
    public ScanResult ScanUrl(Uri url)
    {
      return this.ScanUrls((IEnumerable<Uri>) new Uri[1]{ url }).FirstOrDefault<ScanResult>();
    }

    /// <summary>
    /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
    /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
    /// </summary>
    /// <param name="urlList">The urls to process.</param>
    /// <returns>The scan results.</returns>
    public List<ScanResult> ScanUrls(IEnumerable<string> urlList)
    {
      return this.ScanUrls(this.UrlToUri(urlList));
    }

    /// <summary>
    /// Scan the given URLs. The URLs will be downloaded by VirusTotal and processed.
    /// Note: Before performing your submission, you should retrieve the latest reports on the URLs.
    /// </summary>
    /// <param name="urlList">The urls to process.</param>
    /// <returns>The scan results.</returns>
    public List<ScanResult> ScanUrls(IEnumerable<Uri> urlList)
    {
      IEnumerable<Uri> uris = (IEnumerable<Uri>) (urlList as Uri[] ?? urlList.ToArray<Uri>());
      if (!uris.Any<Uri>())
        throw new ArgumentException("You have to supply an URL.", "urlList");
      RestRequest request = this.PrepareRequest("url/scan", Method.POST);
      request.AddParameter("url", (object) string.Join<Uri>(Environment.NewLine, uris));
      return this.GetResults<List<ScanResult>>(request);
    }

    /// <summary>Gets a scan report from an URL</summary>
    /// <param name="url">The URL you wish to get the report on.</param>
    /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
    /// <returns>A list of reports</returns>
    public UrlReport GetUrlReport(string url, bool scanIfNoReport = false)
    {
      return this.GetUrlReports(this.UrlToUri((IEnumerable<string>) new string[1]{ url }), scanIfNoReport).FirstOrDefault<UrlReport>();
    }

    /// <summary>Gets a scan report from an URL</summary>
    /// <param name="url">The URL you wish to get the report on.</param>
    /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URL if it is not present in the database.</param>
    /// <returns>A list of reports</returns>
    public UrlReport GetUrlReport(Uri url, bool scanIfNoReport = false)
    {
      return this.GetUrlReports((IEnumerable<Uri>) new Uri[1]{ url }, (scanIfNoReport ? 1 : 0) != 0).First<UrlReport>();
    }

    /// <summary>Gets a scan report from a list of URLs</summary>
    /// <param name="urlList">The URLs you wish to get the reports on.</param>
    /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
    /// <returns>A list of reports</returns>
    public List<UrlReport> GetUrlReports(IEnumerable<string> urlList, bool scanIfNoReport = false)
    {
      return this.GetUrlReports(this.UrlToUri(urlList), scanIfNoReport);
    }

    /// <summary>Gets a scan report from a list of URLs</summary>
    /// <param name="urlList">The URLs you wish to get the reports on.</param>
    /// <param name="scanIfNoReport">Set to true if you wish VirusTotal to scan the URLs if it is not present in the database.</param>
    /// <returns>A list of reports</returns>
    public List<UrlReport> GetUrlReports(IEnumerable<Uri> urlList, bool scanIfNoReport = false)
    {
      IEnumerable<Uri> uris = (IEnumerable<Uri>) (urlList as Uri[] ?? urlList.ToArray<Uri>());
      if (!uris.Any<Uri>())
        throw new ArgumentException("You have to supply an URL.", "urlList");
      RestRequest request = this.PrepareRequest("url/report", Method.POST);
      request.AddParameter("resource", (object) string.Join<Uri>(Environment.NewLine, uris));
      if (scanIfNoReport)
        request.AddParameter("scan", (object) 1);
      return this.GetResults<List<UrlReport>>(request);
    }

    /// <summary>Gets a scan report from an IP</summary>
    /// <param name="ip">The IP you wish to get the report on.</param>
    /// <returns>A report</returns>
    public IPReport GetIPReport(string ip)
    {
      return this.GetIPReport(IPAddress.Parse(ip));
    }

    /// <summary>Gets a scan report from an IP</summary>
    /// <param name="ip">The IP you wish to get the report on.</param>
    /// <returns>A report</returns>
    public IPReport GetIPReport(IPAddress ip)
    {
      if (ip == null)
        throw new ArgumentNullException("ip", "You have to supply an IP.");
      if (ip.AddressFamily != AddressFamily.InterNetwork)
        throw new ArgumentException("Only IPv4 addresses are supported", "ip");
      RestRequest request = this.PrepareRequest("ip-address/report", Method.GET);
      request.AddParameter("ip", (object) ip.ToString());
      return this.GetResults<IPReport>(request);
    }

    /// <summary>Gets a scan report from a domain</summary>
    /// <param name="domain">The domain you wish to get the report on.</param>
    /// <returns>A report</returns>
    public DomainReport GetDomainReport(string domain)
    {
      if (string.IsNullOrWhiteSpace(domain))
        throw new ArgumentException("You have to supply a domain.", "domain");
      RestRequest request = this.PrepareRequest("domain/report", Method.GET);
      request.AddParameter("domain", (object) domain);
      return this.GetResults<DomainReport>(request);
    }

    /// <summary>
    /// Creates a comment on a file denoted by its hash and/or scan ID.
    /// </summary>
    /// <param name="file">The file you wish to create a comment on</param>
    /// <param name="comment">The comment you wish to add.</param>
    /// <returns>A ScanResult object containing information about the resource.</returns>
    public ScanResult CreateComment(byte[] file, string comment)
    {
      return this.CreateComment(HashHelper.GetSHA256(file), comment);
    }

    /// <summary>
    /// Creates a comment on a file denoted by its hash and/or scan ID.
    /// </summary>
    /// <param name="file">The file you wish to create a comment on</param>
    /// <param name="comment">The comment you wish to add.</param>
    /// <returns>A ScanResult object containing information about the resource.</returns>
    public ScanResult CreateComment(FileInfo file, string comment)
    {
      return this.CreateComment(HashHelper.GetSHA256(file), comment);
    }

    /// <summary>
    /// Creates a comment on a file denoted by its hash and/or scan ID.
    /// </summary>
    /// <param name="resource">The SHA256 hash or scan ID of the resource.</param>
    /// <param name="comment">The comment you wish to add.</param>
    /// <returns>A ScanResult object containing information about the resource.</returns>
    public ScanResult CreateComment(string resource, string comment)
    {
      this.ValidateResource(resource);
      if (string.IsNullOrWhiteSpace(comment))
        throw new ArgumentException("Comment must not be null or whitespace", "comment");
      RestRequest request = this.PrepareRequest("comments/put", Method.POST);
      request.AddParameter("resource", (object) resource);
      request.AddParameter("comment", (object) comment);
      return this.GetResults<ScanResult>(request);
    }

    /// <summary>
    /// Gives you a link to a file analysis based on its hash.
    /// </summary>
    /// <returns>A link to VirusTotal that contains the report</returns>
    public string GetPublicFileScanLink(string resource)
    {
      this.ValidateResource(resource);
      return string.Format("{0}://www.virustotal.com/file/{1}/analysis/", this.UseTLS ? (object) "https" : (object) "http", (object) resource);
    }

    /// <summary>
    /// Gives you a link to a file analysis based on its hash.
    /// </summary>
    /// <returns>A link to VirusTotal that contains the report</returns>
    public string GetPublicFileScanLink(FileInfo file)
    {
      return this.GetPublicFileScanLink(HashHelper.GetSHA256(file));
    }

    /// <summary>Gives you a link to a URL analysis.</summary>
    /// <returns>A link to VirusTotal that contains the report</returns>
    public string GetPublicUrlScanLink(string url)
    {
      return string.Format("{0}://www.virustotal.com/url/{1}/analysis/", this.UseTLS ? (object) "https" : (object) "http", (object) HashHelper.GetSHA256(this.NormalizeUrl(url)));
    }

    private RestRequest PrepareRequest(string path, Method methodType = Method.POST)
    {
      RestRequest restRequest = new RestRequest(path, methodType);
      string name = "apikey";
      string str = this._apiKey;
      restRequest.AddParameter(name, (object) str);
      return restRequest;
    }

    private T GetResults<T>(RestRequest request)
    {
      RestResponse restResponse = (RestResponse) this._client.Execute((IRestRequest) request);
      if (restResponse.StatusCode == HttpStatusCode.NoContent)
        throw new RateLimitException("You have reached the 4 requests pr. min. limit of VirusTotal");
      if (restResponse.StatusCode == HttpStatusCode.Forbidden)
        throw new AccessDeniedException("You don't have access to the service. Make sure your API key is working correctly.");
      if (restResponse.ErrorException != null)
        throw restResponse.ErrorException;
      if (restResponse.StatusCode != HttpStatusCode.OK)
        throw new Exception("API gave error code " + (object) restResponse.StatusCode);
      if (string.IsNullOrWhiteSpace(restResponse.Content))
        throw new Exception("There were no content in the response.");
      return new JsonDeserializer().Deserialize<T>((IRestResponse) restResponse);
    }

    private string NormalizeUrl(string url)
    {
      return this.CreateUri(url).ToString();
    }

    private IEnumerable<string> GetResourcesFromFiles(IEnumerable<FileInfo> files)
    {
      foreach (FileInfo file in files)
        yield return HashHelper.GetSHA256(file);
    }

    private IEnumerable<string> GetResourcesFromFiles(IEnumerable<byte[]> files)
    {
      foreach (byte[] file in files)
        yield return HashHelper.GetSHA256(file);
    }

    private IEnumerable<string> GetResourcesFromFiles(IEnumerable<Stream> streams)
    {
      foreach (Stream stream in streams)
        yield return HashHelper.GetSHA256(stream);
    }

    private IEnumerable<Uri> UrlToUri(IEnumerable<string> urls)
    {
      foreach (string url in urls)
      {
        Uri uri;
        try
        {
          uri = this.CreateUri(url);
        }
        catch (Exception ex)
        {
          throw new Exception("There was an error converting " + url + " to an uri. See InnerException for details.", ex);
        }
        yield return uri;
        uri = (Uri) null;
      }
    }

    private Uri CreateUri(string url)
    {
      string uriString = url.Trim();
      string lower = uriString.ToLower();
      if (!lower.StartsWith("http://") && !lower.StartsWith("https://"))
        uriString = "http://" + uriString;
      return new Uri(uriString);
    }

    private void ValidateResource(string resource)
    {
      if (string.IsNullOrWhiteSpace(resource))
        throw new ArgumentException("Resource must not be null or whitespace", "resource");
      if (resource.Length != 32 && resource.Length != 40 && (resource.Length != 64 && resource.Length != 75))
        throw new InvalidResourceException("Resource " + resource + " has to be either a MD5, SHA1, SHA256 or scan id");
    }
  }
}
