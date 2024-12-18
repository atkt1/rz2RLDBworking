export function getDeviceInfo(): string {
  const userAgent = window.navigator.userAgent;
  const platform = window.navigator.platform;
  const language = window.navigator.language;
  
  return JSON.stringify({
    userAgent,
    platform,
    language,
    timestamp: new Date().toISOString()
  });
}