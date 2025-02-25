// Program.cs
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// ���� services ������
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ��ǹ�ͧ��õ�駤�� JWT Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // ��Ǩ�ͺ issuer (����͡ token)
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],

        // ��Ǩ�ͺ audience (����Ѻ token)
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"],

        // ��Ǩ�ͺ signing key
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? "YourSuperSecretKeyWithAtLeast32Characters")),

        // ��Ǩ�ͺ���آͧ token
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "JWT API", Version = "v1" });

    // ������ǹ�ͧ JWT Authorization
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

// ��˹� middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// ���� middleware ����Ѻ authentication ��� authorization
app.UseAuthentication();
app.UseAuthorization();

// �����ż������ͧ (��к���ԧ��ô֧�ҡ�ҹ������)
var users = new List<User>
{
    new User { Id = 1, Username = "admin", Password = "password123", Role = "Admin" },
    new User { Id = 2, Username = "user", Password = "password123", Role = "User" }
};

// API ����Ѻ���Ѻ JWT Token (Login)
app.MapPost("/api/login", (LoginRequest loginRequest) =>
{
    // ���Ҽ����ҡ�����Ũ��ͧ
    var user = users.FirstOrDefault(u =>
        u.Username == loginRequest.Username &&
        u.Password == loginRequest.Password);

    if (user == null)
    {
        return Results.Unauthorized();
    }

    // ���ҧ JWT Token
    var token = GenerateJwtToken(user, app.Configuration);

    // �觡�Ѻ token
    return Results.Ok(new { token });
})
.WithName("Login")
.WithOpenApi();

// API �������ͧ��á���׹�ѹ��ǵ�
app.MapGet("/api/public", () =>
{
    return Results.Ok("API ����� public ����ö���¡����������ͧ�� token");
})
.WithName("Public")
.WithOpenApi();

// API ����ͧ��á���׹�ѹ��ǵ� (��ͧ�� token)
app.MapGet("/api/secured", [Authorize] (ClaimsPrincipal user) =>
{
    // �֧�����Ũҡ claims (�����ŷ������� token)
    var username = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var role = user.FindFirst(ClaimTypes.Role)?.Value;

    return Results.Ok(new
    {
        message = "API ����ͧ��á���׹�ѹ��ǵ�",
        username,
        role
    });
})
.WithName("Secured")
.WithOpenApi();

// API ����ͧ����Է��� Admin ��ҹ��
app.MapGet("/api/admin", [Authorize(Roles = "Admin")] () =>
{
    return Results.Ok("API �����Ҷ֧��੾�� Admin ��ҹ��");
})
.WithName("AdminOnly")
.WithOpenApi();

app.Run();

// �ѧ��ѹ����Ѻ���ҧ JWT Token
string GenerateJwtToken(User user, IConfiguration configuration)
{
    // ��˹���� key ����Ѻ�������
    var securityKey = new SymmetricSecurityKey(
        Encoding.UTF8.GetBytes(configuration["Jwt:Key"] ?? "YourSuperSecretKeyWithAtLeast32Characters"));

    // ��˹���š��Է��㹡���������
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    // ��˹� claims (�����ŷ��нѧ���� token)
    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, user.Username),
        new Claim(ClaimTypes.Role, user.Role),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim("UserId", user.Id.ToString())
    };

    // ���ҧ token
    var token = new JwtSecurityToken(
        issuer: configuration["Jwt:Issuer"] ?? "YourIssuer",
        audience: configuration["Jwt:Audience"] ?? "YourAudience",
        claims: claims,
        expires: DateTime.Now.AddHours(1), // token �������� 1 �������
        signingCredentials: credentials
    );

    // �ŧ token �� string ����觡�Ѻ
    return new JwtSecurityTokenHandler().WriteToken(token);
}

// ��������Ѻ�����ż����
public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
}

// ��������Ѻ�Ѻ�����š���������к�
public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}