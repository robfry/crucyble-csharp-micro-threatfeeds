﻿using System;
using System.Net;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Threatfeeds.FIDO.Support.API.Endpoints
{
  public class APIEndpoints
  {
    public static ApiEndpointsClass.PrimaryConfig PrimaryConfig => ApiConfigClean();

    private static ApiEndpointsClass.API GetApiEndpoints()
    {
      var query = "http://127.0.0.1:5984/fido_api_endpoints/_design/api/_view/endpoints";
      var alertRequest = (HttpWebRequest)WebRequest.Create(query);
      var stringreturn = string.Empty;
      var cdbReturn = new ApiEndpointsClass.API();

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(alertRequest);
        if (string.IsNullOrEmpty(stringreturn)) return cdbReturn;
        cdbReturn = JsonConvert.DeserializeObject<ApiEndpointsClass.API>(stringreturn);
        return cdbReturn;
      }
      catch (WebException e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying CouchDB:" + e);
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying CouchDB:" + e);
      }

      return cdbReturn;
    }

    public static ApiEndpointsClass.PrimaryConfig ApiConfigClean()
    {
      var Api = new ApiEndpointsClass.API();

      Api = GetApiEndpoints();

      var api = new ApiEndpointsClass.PrimaryConfig();

      api = Api.rows[0].key.apicall.runtest ? Api.rows[0].key.apicall.test : Api.rows[0].key.apicall.production;
      if (api.globalconfig.ssl) api.host = Api.rows[0].key.apicall.runtest ? @"https://" + Api.rows[0].key.apicall.test.globalconfig.host + @":" + Api.rows[0].key.apicall.test.globalconfig.port + @"/" : @"https://" + Api.rows[0].key.apicall.production.globalconfig.host + @":" + Api.rows[0].key.apicall.production.globalconfig.port + @"/";
      else api.host = Api.rows[0].key.apicall.runtest ? @"http://" + Api.rows[0].key.apicall.test.globalconfig.host + @":" + Api.rows[0].key.apicall.test.globalconfig.port + @"/" : @"http://" + Api.rows[0].key.apicall.production.globalconfig.host + @":" + Api.rows[0].key.apicall.production.globalconfig.port + @"/";
      api.runtest = Api.rows[0].key.apicall.runtest;
      return api;
    }
  }
}
