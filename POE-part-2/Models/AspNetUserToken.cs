using System;
using System.Collections.Generic;

namespace POE_part_2.Models;

public partial class AspNetUserToken
{
    public string UserId { get; set; } = Guid.NewGuid().ToString();  

    public string LoginProvider { get; set; }   

    public string Name { get; set; }    

    public string? Value { get; set; }

    public virtual AspNetUser User { get; set; }    
}
