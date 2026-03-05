using Antivirus.Service;

var builder = Host.CreateApplicationBuilder(args);

// чтобы файлы разрешал смотреть
builder.Services.AddWindowsService();

builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
