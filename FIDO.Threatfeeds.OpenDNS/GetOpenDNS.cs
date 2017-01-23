using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.Event.Queue;
using FIDO.Threatfeeds.FIDO.Support.RabbitMQ;
using FIDO.Threatfeeds.FIDO.Support.Threat.Feeds;

namespace FIDO.Threatfeeds.OpenDNS
{
  internal static class GetOpenDns
  {
    private static void Main(string[] args)
    {
      GetOpenDnsQueue();
    }

    private static void GetOpenDnsQueue()
    {
      try
      {
        while (true)
        {
          GetRabbit.ReceiveNotificationQueue(EventQueue.PrimaryConfig.host, EventQueue.PrimaryConfig.threatfeeds.opendns.exchange, EventQueue.PrimaryConfig.threatfeeds.opendns.queue, ThreatFeedEnum.Opendns);
        }
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught gathering rabbitmq events:" + e);
      }
    }
  }
}
