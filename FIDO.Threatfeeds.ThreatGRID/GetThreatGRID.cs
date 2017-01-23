using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.Event.Queue;
using FIDO.Threatfeeds.FIDO.Support.RabbitMQ;
using FIDO.Threatfeeds.FIDO.Support.Threat.Feeds;

namespace FIDO.Threatfeeds.ThreatGRID
{
  internal static class GetThreatGRID
  {
    private static void Main(string[] args)
    {
      GetThreatGRIDQueue();
    }

    private static void GetThreatGRIDQueue()
    {
      try
      {
        while (true)
        {
          GetRabbit.ReceiveNotificationQueue(EventQueue.PrimaryConfig.host, EventQueue.PrimaryConfig.threatfeeds.threatgrid.exchange, EventQueue.PrimaryConfig.threatfeeds.threatgrid.queue, ThreatFeedEnum.Threatgrid);
          Console.Clear();
        }
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught gathering rabbitmq events:" + e);
      }
    }
  }
}
