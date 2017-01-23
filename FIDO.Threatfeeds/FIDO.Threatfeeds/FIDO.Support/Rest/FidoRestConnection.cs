﻿using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;

namespace FIDO.Threatfeeds.FIDO.Support.Rest
{
  public class RestConnection
  {
    public string RestCall(WebRequest connection)
    {
      var stringreturn = string.Empty;
      
      try
      {
        //Console.WriteLine(@"Making connection to: " + connection.RequestUri + @".");
        using (var response = connection.GetResponse() as HttpWebResponse)
        {
          if (response != null && response.StatusCode == HttpStatusCode.OK)
          {
            using (var respStream = response.GetResponseStream())
            {
              //Thread.Sleep(500);
              if (respStream == null) return string.Empty;
              var reader = new StreamReader(respStream, Encoding.UTF8);
              stringreturn = reader.ReadToEnd();
              var responseStream = response.GetResponseStream();
              responseStream?.Dispose();
              response.Close();
              response.Dispose();
              return stringreturn;
            }
          }
          else if (response != null)
            switch (response.StatusCode)
            {
              case HttpStatusCode.GatewayTimeout:
                FidoEventHandler.SendEmail("Network Error", "REST Failed: {0} Exception caught in REST call area when getting json:" + response);
                break;
              case HttpStatusCode.ServiceUnavailable:
                Console.WriteLine(@"OpenDNS thottling in effecting... sleeping thread for 5 seconds.");
                Thread.Sleep(5000);
                RestCall(connection);
                break;
            }
        }
      }
      catch (WebException e)
      {
        Console.WriteLine(e.GetBaseException().Message + @" " + connection.RequestUri); //+ e.Response.ResponseUri);
        return null;
      }
      catch (Exception e)
      {
        Console.WriteLine(e.GetBaseException().Message + @" " + connection.RequestUri); //+ e.Response.ResponseUri);
        //Fido_EventHandler.SendEmail(e.GetBaseException().Message, "Fido Failed: {0} Exception caught in REST call area when getting json:" + e );
        return null;
      }
      return stringreturn;
    }
  }
}
