using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ARMAPI_Test
{
    public class OfferTerm
    {
        public string Name { get; set; }

        public double? Credit { get; set; }

        public Dictionary<double, double> TieredDiscount { get; set; }

        public List<object> ExcludedMeterIds { get; set; }

        public string EffectiveDate { get; set; }
    }
}
