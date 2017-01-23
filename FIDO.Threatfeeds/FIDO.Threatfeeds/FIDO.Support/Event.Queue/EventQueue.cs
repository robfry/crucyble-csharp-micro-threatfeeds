using System;
using System.Net;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Threatfeeds.FIDO.Support.Event.Queue
{
  public class EventQueue
  {
    public static readonly EventQueueClass.PrimaryConfig PrimaryConfig = QueConfigClean();

    private static EventQueueClass.Queues GetQueues()
    {
      var query = "http://127.0.0.1:5984/fido_configs_queues/_design/queues/_view/map";
      var alertRequest = (HttpWebRequest)WebRequest.Create(query);
      var stringreturn = string.Empty;
      var cdbReturn = new EventQueueClass.Queues();

      try
      {
        var getRest = new RestConnection();
        stringreturn = getRest.RestCall(alertRequest);
        if (string.IsNullOrEmpty(stringreturn)) return cdbReturn;
        cdbReturn = JsonConvert.DeserializeObject<EventQueueClass.Queues>(stringreturn);
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

    private static EventQueueClass.PrimaryConfig QueConfigClean()
    {
      var Que = GetQueues();
      if (Que == null) throw new ArgumentNullException("Que");
      var que = Que.rows[0].key.queues.runtest ? Que.rows[0].key.queues.test : Que.rows[0].key.queues.production;
      if (que.globalconfig.ssl) que.host = Que.rows[0].key.queues.runtest ? Que.rows[0].key.queues.test.globalconfig.host : Que.rows[0].key.queues.production.globalconfig.host;
      else que.host = Que.rows[0].key.queues.runtest ? Que.rows[0].key.queues.test.globalconfig.host : Que.rows[0].key.queues.production.globalconfig.host;
      que.runtest = Que.rows[0].key.queues.runtest;
      return que;
    }

  }
}
