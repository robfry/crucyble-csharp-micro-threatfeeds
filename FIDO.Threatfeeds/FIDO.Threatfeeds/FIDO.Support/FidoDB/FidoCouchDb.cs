using System;
using System.Net;
using System.Net.Http;
using System.Text;
using FIDO.Threatfeeds.FIDO.Support.API.Endpoints;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.Etc;
using FIDO.Threatfeeds.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Threatfeeds.FIDO.Support.FidoDB
{
  public class FidoCouchDb
  {

    public string WriteToDBFactory(FidoReturnValues lFidoReturnValues)
    {
      var strJson = SerializeJson.Serialize(lFidoReturnValues);
      //var formatJson = new Fido_CouchDB_Detector();
      //var threat = formatJson.ReturnJson(lFidoReturnValues);
      //WriteThreatToCouchDB(threat);
      if (!string.IsNullOrEmpty(lFidoReturnValues.UUID))
      {
        WriteAlertToCouchDB(strJson, lFidoReturnValues.UUID);
      }
      else
      {
        var uuid = WriteAlertToCouchDB(strJson);
        return uuid;
      }

      return string.Empty;
    }

    private void WriteAlertToCouchDB(string strJson, string uuid)
    {
      Console.WriteLine(@"Writing alert to CouchDB.");
      var query = APIEndpoints.PrimaryConfig.host + APIEndpoints.PrimaryConfig.fido_events_alerts.dbname + "/" + uuid;
      var client = new HttpClient { BaseAddress = new Uri(query) };
      var request = new HttpRequestMessage(HttpMethod.Put, query) { Content = new StringContent(strJson, Encoding.UTF8) };

      try
      {
        var result = client.SendAsync(request).Result;
        if (!result.IsSuccessStatusCode)
        {
          Console.WriteLine(@"Alert failed to write to DB.");
          throw new Exception();
        }
        else
        {
          Console.WriteLine(@"Alert written to DB.");
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in write to CouchDB alert area:" + e);
      }
    }

    private string WriteAlertToCouchDB(string strJson)
    {
      Console.WriteLine(@"Writing alert to CouchDB.");
      var uuid = GetUUID();
      var query = APIEndpoints.PrimaryConfig.host + APIEndpoints.PrimaryConfig.fido_events_alerts.dbname + "/" + uuid.UUIDS[0];
      var client = new HttpClient { BaseAddress = new Uri(query) };
      var request = new HttpRequestMessage(HttpMethod.Put, query) { Content = new StringContent(strJson, Encoding.UTF8) };

      try
      {
        var result = client.SendAsync(request).Result;
        if (!result.IsSuccessStatusCode) return string.Empty;
        Console.WriteLine(@"Alert written to DB."); 
        return uuid.UUIDS[0];
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in write to CouchDB alert area:" + e);
      }
      return string.Empty;
    }

    private void WriteThreatToCouchDB(string strJson)
    {
      Console.WriteLine(@"Writing threat data to CouchDB.");
      var uuid = GetUUID();
      var query = APIEndpoints.PrimaryConfig.host + APIEndpoints.PrimaryConfig.fido_events_alerts + "/" + uuid.UUIDS[0];
      var client = new HttpClient { BaseAddress = new Uri(query) };
      var request = new HttpRequestMessage(HttpMethod.Put, query) { Content = new StringContent(strJson, Encoding.UTF8) };

      try
      {
        var result = client.SendAsync(request).Result;
        if (result.IsSuccessStatusCode)
        {
          Console.WriteLine(@"Threat information written to DB.");
        }
      }

      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in write to CouchDB threat area:" + e);
      }
    }

    private CouchDBUUID GetUUID()
    {
      var uuid = new CouchDBUUID();
      var request = APIEndpoints.PrimaryConfig.host + "_uuids";
        //@"http://127.0.0.1:5984/_uuids";
      var connection = (HttpWebRequest)WebRequest.Create(request);
      connection.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        var stringreturn = getREST.RestCall(connection);
        var jsonRet = JsonConvert.DeserializeObject<CouchDBUUID>(stringreturn);
        if (string.IsNullOrEmpty(jsonRet.ToString())) return uuid;
        uuid = jsonRet;
        return uuid;
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in GetUUID of CouchDB getting UUID:" + e);
      }


      return uuid;
    }

    private class CouchDBUUID
    {
      [JsonProperty("uuids")]
      internal string[] UUIDS { get; set; }
    }
  }
}
