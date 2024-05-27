using System;
using System.Collections.Generic;

namespace POE_part_2.Models;

public partial class Transaction
{
    public string TransactionId { get; set; } = Guid.NewGuid().ToString();

    public string UserId { get; set; } 

    public string CourierId { get; set; } 

    public string? Status { get; set; } 

    public decimal TotalPrice { get; set; }

    public TimeOnly TimeOfTransaction { get; set; }

    public DateOnly DateOfTransaction { get; set; }

    public string? AddressOfArrival { get; set; } 

    public int TotalNumProducts { get; set; }

    public virtual Courier Courier { get; set; } 

    public virtual ICollection<TransactionProduct> TransactionProducts { get; set; } = new List<TransactionProduct>();

    public virtual AspNetUser User { get; set; } 
}
