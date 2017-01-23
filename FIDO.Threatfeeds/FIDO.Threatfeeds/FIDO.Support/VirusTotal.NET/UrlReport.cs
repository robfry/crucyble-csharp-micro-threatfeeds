// Decompiled with JetBrains decompiler
// Type: VirusTotalNET.Objects.UrlReport
// Assembly: VirusTotal.NET, Version=1.3.1.0, Culture=neutral, PublicKeyToken=null
// MVID: 2B160AD8-F9AD-46F3-A2B1-F9B9E38BD041
// Assembly location: D:\repository\repo\vs2015\Security\FIDO.Threatfeeds\FIDO.Threatfeeds\packages\VirusTotal.NET.1.3.1.0\lib\VirusTotal.NET.dll

using System;
using System.Collections.Generic;

namespace FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET
{
  public class UrlReport
  {
    /// <summary>Filescan Id of the resource.</summary>
    public string FilescanId { get; set; }

    /// <summary>A permanent link that points to this specific scan.</summary>
    public string Permalink { get; set; }

    /// <summary>How many engines flagged this resource.</summary>
    public int Positives { get; set; }

    /// <summary>
    /// Contains the id of the resource. Can be a SHA256, MD5 or other hash type.
    /// </summary>
    public string Resource { get; set; }

    /// <summary>
    /// The response code. Use this to determine the status of the report.
    /// </summary>
    public ReportResponseCode ResponseCode { get; set; }

    /// <summary>The date the resource was last scanned.</summary>
    public DateTime ScanDate { get; set; }

    /// <summary>Contains the scan id for this result.</summary>
    public string ScanId { get; set; }

    public class Scan
    {
      public string Key { get; set; }
      public ScanEngine Value { get; set; }
    }


    /// <summary>The scan results from each engine.</summary>
    public List<Scan> Scans { get; set; }

    /// <summary>How many engines scanned this resource.</summary>
    public int Total { get; set; }

    /// <summary>
    /// Contains the message that corrosponds to the reponse code.
    /// </summary>
    public string URL { get; set; }

    /// <summary>
    /// Contains the message that corrosponds to the reponse code.
    /// </summary>
    public string VerboseMsg { get; set; }
  }
}
