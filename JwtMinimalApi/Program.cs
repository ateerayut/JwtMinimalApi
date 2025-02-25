// Program.cs
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// เพิ่ม services ที่จำเป็น
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ส่วนของการตั้งค่า JWT Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // ตรวจสอบ issuer (ผู้ออก token)
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],

        // ตรวจสอบ audience (ผู้รับ token)
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"],

        // ตรวจสอบ signing key
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? "YourSuperSecretKeyWithAtLeast32Characters")),

        // ตรวจสอบอายุของ token
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "JWT API", Version = "v1" });

    // เพิ่มส่วนของ JWT Authorization
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },new string[] {}
        }
    });
});

builder.Services.AddAuthorization();

var app = builder.Build();

// กำหนด middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// เพิ่ม middleware สำหรับ authentication และ authorization
app.UseAuthentication();
app.UseAuthorization();

// ข้อมูลผู้ใช้จำลอง (ในระบบจริงควรดึงจากฐานข้อมูล)
var users = new List<User>
{
    new User { Id = 1, Username = "admin", Password = "password123", Role = "Admin" },
    new User { Id = 2, Username = "user", Password = "password123", Role = "User" }
};

// API สำหรับขอรับ JWT Token (Login)
app.MapPost("/api/login", (LoginRequest loginRequest) =>
{
    // ค้นหาผู้ใช้จากข้อมูลจำลอง
    var user = users.FirstOrDefault(u =>
        u.Username == loginRequest.Username &&
        u.Password == loginRequest.Password);

    if (user == null)
    {
        return Results.Unauthorized();
    }

    // สร้าง JWT Token
    var token = GenerateJwtToken(user, app.Configuration);

    // ส่งกลับ token
    return Results.Ok(new { token });
})
.WithName("Login")
.WithOpenApi();

// API ที่ไม่ต้องการการยืนยันตัวตน
app.MapGet("/api/public", () =>
{
    return Results.Ok("API นี้เป็น public สามารถเรียกใช้ได้โดยไม่ต้องมี token");
})
.WithName("Public")
.WithOpenApi();

// API ที่ต้องการการยืนยันตัวตน (ต้องมี token)
app.MapGet("/api/secured", [Authorize] (ClaimsPrincipal user) =>
{
    // ดึงข้อมูลจาก claims (ข้อมูลที่อยู่ใน token)
    var username = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var role = user.FindFirst(ClaimTypes.Role)?.Value;

    return Results.Ok(new
    {
        message = "API นี้ต้องการการยืนยันตัวตน",
        username,
        role
    });
})
.WithName("Secured")
.WithOpenApi();

// API ที่ต้องการสิทธิ์ Admin เท่านั้น
app.MapGet("/api/admin", [Authorize(Roles = "Admin")] () =>
{
    return Results.Ok("API นี้เข้าถึงได้เฉพาะ Admin เท่านั้น");
})
.WithName("AdminOnly")
.WithOpenApi();

app.Run();

// ฟังก์ชันสำหรับสร้าง JWT Token
string GenerateJwtToken(User user, IConfiguration configuration)
{
    // กำหนดค่า key สำหรับเข้ารหัส
    var securityKey = new SymmetricSecurityKey(
        Encoding.UTF8.GetBytes(configuration["Jwt:Key"] ?? "YourSuperSecretKeyWithAtLeast32Characters"));

    // กำหนดอัลกอริทึมในการเข้ารหัส
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    // กำหนด claims (ข้อมูลที่จะฝังไว้ใน token)
    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, user.Username),
        new Claim(ClaimTypes.Role, user.Role),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim("UserId", user.Id.ToString())
    };

    // สร้าง token
    var token = new JwtSecurityToken(
        issuer: configuration["Jwt:Issuer"] ?? "YourIssuer",
        audience: configuration["Jwt:Audience"] ?? "YourAudience",
        claims: claims,
        expires: DateTime.Now.AddHours(1), // token หมดอายุใน 1 ชั่วโมง
        signingCredentials: credentials
    );

    // แปลง token เป็น string และส่งกลับ
    return new JwtSecurityTokenHandler().WriteToken(token);
}

// คลาสสำหรับข้อมูลผู้ใช้
public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
}

// คลาสสำหรับรับข้อมูลการเข้าสู่ระบบ
public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}