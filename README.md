# custom-mojang-auth
A small library that allows your mod to automatically sign in to your custom server using the players mojang account. 
Works for any minecraft version.
This mod allows a server to reliably 
## Usage
### Client

In your mod initialize the Authenticator:
```java
String accessToken;
UUID uuid;
java.net.Proxy proxy;
String messagePrefix //optional
ClientAuth.initialize(accessToken, uuid, proxy, messagePrefix);
```
The way accessToken, uuid and proxy are obtained depends on the Minecraft Version.
Obtaining the uuid of the player is pretty trivial, it can usually be found this way:
```java
UUID uuid = net.minecraft.client.MinecraftClient.getInstance().getSession().getProfile().getId(); //1.16.1
```
or
```java
UUID uuid = net.minecraft.client.MinecraftClient.getInstance().getSession().getUuidOrNull(); //1.20.2
```
Obtaining the accessToken is relatively easy as well:
```java
String accessToken= net.minecraft.client.MinecraftClient.getInstance().getSession().getAccessToken();
```
Obtaining the proxy can be a bit more difficult.
In every version that I know of it is initialized in net.minecraft.client.mainmMian.main(String args[]). Just follow the Proxy object from here,
usually it's given to the net.minecraft.client.MinecraftClient constructor, and find a place where you can easily obtain it either via a method call, reflection, a mixin etc
In 1.20.2 the proxy can be obtained this way:
```java
Field field =net.minecraft.client.MinecraftClient.class.getField("authenticationService");
field.setAccessible(true);
java.net.Proxy proxy =((com.mojang.authlib.yggdrasil.YggdrasilAuthenticationService)field.get(net.minecraft.client.MinecraftClient.getInstance())).getProxy();
```
In 1.16.1 the proxy can be obtained this way:
```java
java.net.Proxy proxy = ((com.mojang.authlib.yggdrasil.YggdrasilMinecraftSessionService)net.minecraft.client.MinecraftClient.getInstance().getSessionService()).getAuthenticationService().getProxy();
```
If you need help locating any of the fields for your version, feel free to dm me on discord: void_x_walker
### Server
Install the library:
```
npm install custom-mojang-auth  
```
use the following function to verify that a payload has been signed by the client.
```javascript
function isValid(uuid, randomLong, data, date, publicKeyString, signatureBytes, payload)
```
where payload is an array.
## Privacy
The client simply signs messages using it's private key, which can then be send to a server. No login information, or other compromising information ever leaves the client's machine.
