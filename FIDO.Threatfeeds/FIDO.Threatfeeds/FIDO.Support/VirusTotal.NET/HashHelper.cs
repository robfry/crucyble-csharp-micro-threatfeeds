// Decompiled with JetBrains decompiler
// Type: VirusTotalNET.HashHelper
// Assembly: VirusTotal.NET, Version=1.3.1.0, Culture=neutral, PublicKeyToken=null
// MVID: 2B160AD8-F9AD-46F3-A2B1-F9B9E38BD041
// Assembly location: D:\repository\repo\vs2015\Security\FIDO.Threatfeeds\FIDO.Threatfeeds\packages\VirusTotal.NET.1.3.1.0\lib\VirusTotal.NET.dll

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET
{
  public static class HashHelper
  {
    public static string GetSHA256(byte[] buffer)
    {
      using (MemoryStream memoryStream = new MemoryStream(buffer))
        return HashHelper.GetSHA256((Stream) memoryStream);
    }

    public static string GetSHA256(string content)
    {
      using (MemoryStream memoryStream = new MemoryStream(Encoding.UTF8.GetBytes(content)))
        return HashHelper.GetSHA256((Stream) memoryStream);
    }

    public static string GetSHA256(FileInfo file)
    {
      if (!file.Exists)
        throw new FileNotFoundException("File not found.", file.FullName);
      using (FileStream fileStream = file.OpenRead())
        return HashHelper.GetSHA256((Stream) fileStream);
    }

    public static string GetSHA256(Stream stream)
    {
      if (stream == null || stream.Length == 0L)
        throw new ArgumentException("You must provide a valid stream.", "stream");
      using (SHA256 shA256 = SHA256.Create())
        return HashHelper.ByteArrayToHex(shA256.ComputeHash(stream));
    }

    public static string GetSHA1(byte[] buffer)
    {
      using (MemoryStream memoryStream = new MemoryStream(buffer))
        return HashHelper.GetSHA1((Stream) memoryStream);
    }

    public static string GetSHA1(string content)
    {
      using (MemoryStream memoryStream = new MemoryStream(Encoding.UTF8.GetBytes(content)))
        return HashHelper.GetSHA1((Stream) memoryStream);
    }

    public static string GetSHA1(FileInfo file)
    {
      if (!file.Exists)
        throw new FileNotFoundException("File not found.", file.FullName);
      using (FileStream fileStream = file.OpenRead())
        return HashHelper.GetSHA1((Stream) fileStream);
    }

    public static string GetSHA1(Stream stream)
    {
      if (stream == null || stream.Length == 0L)
        throw new ArgumentException("You must provide a valid stream.", "stream");
      using (SHA1 shA1 = SHA1.Create())
        return HashHelper.ByteArrayToHex(shA1.ComputeHash(stream));
    }

    public static string GetMD5(byte[] buffer)
    {
      using (MemoryStream memoryStream = new MemoryStream(buffer))
        return HashHelper.GetMD5((Stream) memoryStream);
    }

    public static string GetMD5(string content)
    {
      using (MemoryStream memoryStream = new MemoryStream(Encoding.UTF8.GetBytes(content)))
        return HashHelper.GetMD5((Stream) memoryStream);
    }

    public static string GetMD5(FileInfo file)
    {
      if (!file.Exists)
        throw new FileNotFoundException("File not found.", file.FullName);
      using (FileStream fileStream = file.OpenRead())
        return HashHelper.GetMD5((Stream) fileStream);
    }

    public static string GetMD5(Stream stream)
    {
      if (stream == null || stream.Length == 0L)
        throw new ArgumentException("You must provide a valid stream.", "stream");
      using (MD5 md5 = MD5.Create())
        return HashHelper.ByteArrayToHex(md5.ComputeHash(stream));
    }

    public static string ByteArrayToHex(byte[] buffer)
    {
      StringBuilder stringBuilder = new StringBuilder(buffer.Length * 2);
      foreach (byte num in buffer)
        stringBuilder.AppendFormat("{0:x2}", (object) num);
      return stringBuilder.ToString();
    }
  }
}
