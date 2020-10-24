---
title: "Flare-On 7 — 05 TKApp"
date: 2020-10-23T21:29:45+03:00
draft: false
author: "explained.re"
tags: ["flare-on"]
categories: ["write-up", "ctf"]

lightgallery: true


toc:
  enable: false

---

{{< admonition info "Challenge Description" >}}

Now you can play Flare-On on your watch! As long as you still have an arm left to put a watch on, or emulate the watch's operating system with sophisticated developer tools.
{{< /admonition >}}

In this one, we get a `.tpk` file which is a *Tizen OS* application that's used in smartwatches. Let's extract the files from this archive to see what we're dealing with.

```bash
$ unzip TKApp.tpk
$ ls
Message.txt      TKApp.tpk             bin  res     signature1.xml
TKApp.deps.json  author-signature.xml  lib  shared  tizen-manifest.xml
```

Looks like we have an application manifest, so let's look at it first.

```xml
<!-- tizen-manifest.xml -->
<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.flare-on.TKApp" version="1.0.0" api-version="5.5" xmlns="http://tizen.org/ns/packages">
    <author href="http://www.flare-on.com" />
    <profile name="wearable" />
    <ui-application appid="com.flare-on.TKApp" exec="TKApp.dll" multiple="false" nodisplay="false" taskmanage="true" api-version="6" type="dotnet" launch_mode="single">
        <label>TKApp</label>
        <icon>TKApp.png</icon>
        <metadata key="http://tizen.org/metadata/prefer_dotnet_aot" value="true" />
        <metadata key="its" value="magic" />
        <splash-screens />
    </ui-application>
    <shortcut-list />
    <privileges>
        <privilege>http://tizen.org/privilege/location</privilege>
        <privilege>http://tizen.org/privilege/healthinfo</privilege>
    </privileges>
    <dependencies />
    <provides-appdefined-privileges />
</manifest>
```

We have here the main UI application which has the ID `com.flare-on.TKApp`, and it uses the executable file `TKApp.dll`, so we can jump straight into it.

```bash
$ file bin/TKApp.dll                                                                                            130 ↵
bin/TKApp.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

Since this is a .net executable, we'll fire up *[DNSpy](https://github.com/dnSpy/dnSpy/releases).* We can start by hitting `Ctrl+Shift+K` for searching, and search for "flag". We do get a label with that name in `TKApp.UnlockPage`. In the `UnlockPage` class, we see a function called `IsPasswordCorrect`, let's get this password. 

```csharp
private bool IsPasswordCorrect(string password)
{
	return password == Util.Decode(TKData.Password);
}
```

We'll take the `TKDate.Password` and the `Decode` functions and run it in Python.

```python
password = [62, 38, 63, 63, 54, 39, 59, 50, 39]
''.join([chr(c ^ 83) for c in password])
# Result:
# 'mullethat'
```

The correct password is `mullethat`. Now let's see if anyone's using this value. Right-clicking and hitting *Analyze* on `IsPasswordCorrect`, then looking at the *Used by* list, we see that `OnLoginButtonClicked` is using this function.

```csharp
private async void OnLoginButtonClicked(object sender, EventArgs e)
		{
			if (this.IsPasswordCorrect(this.passwordEntry.Text))
			{
				App.IsLoggedIn = true;
				App.Password = this.passwordEntry.Text;
				base.Navigation.InsertPageBefore(new MainPage(), this);
				await base.Navigation.PopAsync();
			}
			else
			{
				Toast.DisplayText("Unlock failed!", 2000);
				this.passwordEntry.Text = string.Empty;
			}
		}
```

After checking if the password is correct, it's stored in the `App.Password` field. We'll use *Analyze* again to see who's accessing this and this will bring us to `GetImage`. This function uses decode some data using our password (among other things) and sets this as the image of the application. This can potentially be the image of our flag so let's execute this in Python as well. We'll need to get a few elements for that:

1. `Password` - already got that.
2. `Desc` - by analyzing and looking at who's setting this value, we get to `GalleryPage.IndexPage_CurrentPageChanged` which sets this field to the value of the image description of the file `gallery/05.jpg`. It's easy to get this using:

    ```bash
    $ exiftool res/gallery/05.jpg | grep -i description                                                                                                                                        1 ↵
    Image Description               : **water**
    ```

3. `Note` - once again, we'll analyze until we get to the one who sets this value, which is `TodoPage.SetupList` 

    ```csharp
    private void SetupList()
    		{
    			List<TodoPage.Todo> list = new List<TodoPage.Todo>();
    			if (!this.isHome)
    			{
    				list.Add(new TodoPage.Todo("go home", "and enable GPS", false));
    			}
    			else
    			{
    				TodoPage.Todo[] collection = new TodoPage.Todo[]
    				{
    					new TodoPage.Todo("hang out in tiger cage", "and survive", true),
    					new TodoPage.Todo("unload Walmart truck", "keep steaks for dinner", false),
    					new TodoPage.Todo("yell at staff", "maybe fire someone", false),
    					new TodoPage.Todo("say no to drugs", "unless it's a drinking day", false),
    					new TodoPage.Todo("listen to some tunes", "https://youtu.be/kTmZnQOfAF8", true)
    				};
    				list.AddRange(collection);
    			}
    			List<TodoPage.Todo> list2 = new List<TodoPage.Todo>();
    			foreach (TodoPage.Todo todo in list)
    			{
    				if (!todo.Done)
    				{
    					list2.Add(todo);
    				}
    			}
    			this.mylist.ItemsSource = list2;
    			**App.Note = list2[0].Note;**
    		}
    ```

    From here we need the note of the first item which is not done yet, and we get `keep steaks for dinner`.

4. `Step` - in a similar way, we get to `MainPage.PedDataUpdate` who sets it in the following line:

    ```csharp
    App.Step = Application.Current.ApplicationInfo.Metadata["its"];
    ```

    The `ApplicationInfo` is set in the manifest xml we saw at the beginning:

    ```xml
    <metadata key="its" value="**magic**" />
    ```

    We get `magic`.

5. `Runtime.dll` - the program accesses it using the resource manager, we can simply save this file from the Resources dialog in *DNSpy* by right-clicking and hitting *save.*

{{< image src="images/image.png" >}}

The decoding process contains SHA256 and base64, and if we examine the `Util.GetString` function we see it's Rijndael (AES).

Once we got all this, we can write the algorithm ourselves.

```python
from malduck import sha256, aes, base64

password = "mullethat"
desc = "water"
note = "keep steaks for dinner"
step = "magic"

text = "".join([
				desc[2],
				password[6],
				password[4],
				note[4],
				note[0],
				note[17],
				note[18],
				note[16],
				note[11],
				note[13],
				note[12],
				note[15],
				step[4],
				password[6],
				desc[1],
				password[2],
				password[2],
				password[4],
				note[18],
				step[2],
				password[4],
				note[5],
				note[4],
				desc[0],
				desc[3],
				note[15],
				note[8],
				desc[4],
				desc[3],
				note[4],
				step[2],
				note[13],
				note[18],
				note[18],
				note[8],
				note[4],
				password[0],
				password[7],
				note[0],
				password[4],
				note[11],
				password[6],
				password[4],
				desc[4],
				desc[3]
			])

key = sha256(text.encode())   # rijndaelManaged.Key

iv = b"NoSaltOfTheEarth"  # rijndaelManaged.IV

with open("Runtime.dll" , "rb") as f:
    # decrypt
    plaintext = aes.cbc.decrypt(key, iv, f.read())

with open("decrypted_Runtime.jpeg", "wb") as f: f.write(base64(plaintext))
```

Running this and opening the image we get the flag.

{{< image src="images/decrypted_Runtime_base64_decoded.jpeg" >}}

Flag: [`n3ver_go1ng_to_recov3r@flare-on.com`](mailto:n3ver_go1ng_to_recov3r@flare-on.com).