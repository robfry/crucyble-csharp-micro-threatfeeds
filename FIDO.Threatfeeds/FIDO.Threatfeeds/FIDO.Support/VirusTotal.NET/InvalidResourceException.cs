// Decompiled with JetBrains decompiler
// Type: VirusTotalNET.Exceptions.InvalidResourceException
// Assembly: VirusTotal.NET, Version=1.3.1.0, Culture=neutral, PublicKeyToken=null
// MVID: 2B160AD8-F9AD-46F3-A2B1-F9B9E38BD041
// Assembly location: D:\repository\repo\vs2015\Security\FIDO.Threatfeeds\FIDO.Threatfeeds\packages\VirusTotal.NET.1.3.1.0\lib\VirusTotal.NET.dll

using System;

namespace FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET
{
  public class InvalidResourceException : Exception
  {
    public InvalidResourceException(string message)
      : base(message)
    {
    }
  }
}
