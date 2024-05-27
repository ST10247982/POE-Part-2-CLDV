using System;
using System.Collections.Generic;

namespace POE_part_2.Models;

public partial class TransactionProduct
{
    public string TransactionProductsId { get; set; } = Guid.NewGuid().ToString();

    public string ArtworkId { get; set; } 

    public string TransactionId { get; set; } 

    public int Quantity { get; set; }

    public decimal TotalPriceContribution { get; set; }

    public virtual ArtWork Artwork { get; set; } 

    public virtual Transaction Transaction { get; set; } 
}
