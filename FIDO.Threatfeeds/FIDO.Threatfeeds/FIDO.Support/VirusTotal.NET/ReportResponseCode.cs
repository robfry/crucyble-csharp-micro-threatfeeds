﻿// Decompiled with JetBrains decompiler
// Type: VirusTotalNET.Objects.ReportResponseCode
// Assembly: VirusTotal.NET, Version=1.3.1.0, Culture=neutral, PublicKeyToken=null
// MVID: 2B160AD8-F9AD-46F3-A2B1-F9B9E38BD041
// Assembly location: D:\repository\repo\vs2015\Security\FIDO.Threatfeeds\FIDO.Threatfeeds\packages\VirusTotal.NET.1.3.1.0\lib\VirusTotal.NET.dll

namespace FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET
{
  public enum ReportResponseCode
  {
    StillQueued = -2,
    Error = -1,
    NotPresent = 0,
    Present = 1,
  }
}
