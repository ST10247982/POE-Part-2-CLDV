using System;
using System.Collections.Generic;

namespace POE_part_2.Models;

public partial class Courier
{
    public string CourierId { get; set; } = Guid.NewGuid().ToString();

    public string? CourierName { get; set; } 

    public string? CourierAddress { get; set; } 

    public virtual ICollection<Transaction> Transactions { get; set; } = new List<Transaction>();
}
