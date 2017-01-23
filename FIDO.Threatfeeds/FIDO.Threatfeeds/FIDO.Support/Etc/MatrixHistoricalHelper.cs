using System.Collections.Generic;

namespace FIDO.Threatfeeds.FIDO.Support.Etc
{
  public class MatrixHistoricalHelper
  {
    public class Scoring
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }

      public class Value
      {
        public int score { get; set; }
        public int weight { get; set; }
        public int incrementer { get; set; }
        public int multiplier { get; set; }
        public int count { get; set; }
      }

      public class Row
      {
        public string id { get; set; }
        public object key { get; set; }
        public Value value { get; set; }
      }
    }

    public class HostReturn
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }

      public class Artifacts
      {
        public List<string> Hash { get; set; }
        public object Domain { get; set; }
        public List<object> DstIP { get; set; }
        public string TimeOccurred { get; set; }
        public int PreviousScore { get; set; }
      }

      public class Row
      {
        public string id { get; set; }
        public string key { get; set; }
        public Artifacts value { get; set; }
      }
    }

    public class HistoricalReturn
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }

      public class Value
      {
        public string TimeOccurred { get; set; }
        public string Detector { get; set; }
      }

      public class Row
      {
        public string id { get; set; }
        public string key { get; set; }
        public Value value { get; set; }
      }
    }
  }
}
