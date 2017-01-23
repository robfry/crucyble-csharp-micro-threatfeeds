// Decompiled with JetBrains decompiler
// Type: VirusTotalNET.Objects.ScanResult
// Assembly: VirusTotal.NET, Version=1.3.1.0, Culture=neutral, PublicKeyToken=null
// MVID: 2B160AD8-F9AD-46F3-A2B1-F9B9E38BD041
// Assembly location: D:\repository\repo\vs2015\Security\FIDO.Threatfeeds\FIDO.Threatfeeds\packages\VirusTotal.NET.1.3.1.0\lib\VirusTotal.NET.dll

namespace FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET
{
  public class ScanResult
  {
    /// <summary>MD5 hash of the resource.</summary>
    public string MD5 { get; set; }

    /// <summary>A unique link to this particular scan result.</summary>
    public string Permalink { get; set; }

    /// <summary>Id of the resource.</summary>
    public string Resource { get; set; }

    /// <summary>
    /// The scan response code. Use this to determine the status of the scan.
    /// </summary>
    public ScanResponseCode ResponseCode { get; set; }

    /// <summary>The unique scan id of the resource.</summary>
    public string ScanId { get; set; }

    /// <summary>SHA256 hash of the resource.</summary>
    public string SHA1 { get; set; }

    /// <summary>SHA256 hash of the resource.</summary>
    public string SHA256 { get; set; }

    /// <summary>
    /// Contains a verbose message that corrosponds to the reponse code.
    /// </summary>
    public string VerboseMsg { get; set; }
  }
}
