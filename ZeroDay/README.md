In a effort to validate the capability of IntDroid on detecting real-world
zero-day malware, we leverage our 8,253 samples to train a classifier by
using 1NN algorithm. Next, we crawl 5,000 apps from GooglePlay
market and feed them to the trained 1NN classifier. IntDroid is able to discover
28 zero-day malware among 5,000 GooglePlay apps, 1 of them has
been downloaded and installed by more than 10 million users, and
1 of them is not reported as malware by existing tools.


<table border=0 cellpadding=0 cellspacing=0 width=881 style='border-collapse:
 collapse;table-layout:fixed;width:661pt'>
 <col class=xl65 width=556 style='mso-width-source:userset;mso-width-alt:17792;
 width:417pt'>
 <col class=xl65 width=76 style='mso-width-source:userset;mso-width-alt:2432;
 width:57pt'>
 <col class=xl65 width=127 style='mso-width-source:userset;mso-width-alt:4064;
 width:95pt'>
 <col class=xl65 width=122 style='mso-width-source:userset;mso-width-alt:3904;
 width:92pt'>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 width=556 style='height:13.5pt;width:417pt'>SHA256</td>
  <td class=xl65 width=76 style='width:57pt'>IntDroid</td>
  <td class=xl65 width=127 style='width:95pt'>VirusTotal</td>
  <td class=xl65 width=122 style='width:92pt'>#installations</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>001DD69A26EF861B03206DF17C8804AF09EF4264AE270E6437FDC82253910058</td>
  <td class=xl65>1</td>
  <td class=xl65>1</td>
  <td class=xl65>10,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>15B50DCFB37B99E164ED6B98248D7E589638ACD5CFAA828E4245E26C2BBD829A</td>
  <td class=xl65>1</td>
  <td class=xl65>7</td>
  <td class=xl65>100,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>24576C3FDB39820522B6C37F5A339F52F0F1A1DB861454F197DB77998CAC63CC</td>
  <td class=xl65>1</td>
  <td class=xl65>4</td>
  <td class=xl65></td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>3C7EEDC7D7D22B7F0E2C28EFB8316B82B4EBAE575401954BEC8F75557AC4E65C</td>
  <td class=xl65>1</td>
  <td class=xl65>5</td>
  <td class=xl65>50,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>3ECF4F75D70BD03454A37BCD05405A5AF50A8858BAB27EAF734E1BEDE1DD323D</td>
  <td class=xl65>1</td>
  <td class=xl65>5</td>
  <td class=xl65>1,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>443B2BF3DB9E0D597132D54536E92020F17700FC6EC14ABA4963D5415EACD4CA</td>
  <td class=xl65>1</td>
  <td class=xl65>7</td>
  <td class=xl65>10,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>513D6535A8A69D4BE97F2F38E21491D253C6E8B24A20A94616C0B09B5905E674</td>
  <td class=xl65>1</td>
  <td class=xl65>4</td>
  <td class=xl65>50,000+</td>
 </tr>
 <tr class=xl66 height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>67996AF2935A1CF8DB4B49D005F9F0A4DD069BD9E0D2D8B1FC5C425D6E56EC58</td>
  <td class=xl65>1</td>
  <td class=xl65>5</td>
  <td class=xl65>5,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>6D1023A81563A1A16915CE3DD600596BA76216E11203F3D50BE469C88FA3A956</td>
  <td class=xl65>1</td>
  <td class=xl65>6</td>
  <td class=xl65>100,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>8D24042E5DB333C0B98237C26557DDBEC3D9956096D70513D440E7EC5E5A13FC</td>
  <td class=xl65>1</td>
  <td class=xl65>4</td>
  <td class=xl65>5,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>957168C8248E70CA40C946498996099421825EBF7C0CCC91A377CC4418C99946</td>
  <td class=xl65>1</td>
  <td class=xl65>5</td>
  <td class=xl65></td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>A12241E17238B76EDED89A8A50259947C00793EFCD45D9D06B0E663465C5C0B3</td>
  <td class=xl65>1</td>
  <td class=xl65>5</td>
  <td class=xl65>5,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>A3A71F8A14399C819BEA5B4B93D7A6FA02BBA2D48AD9D9274E303E5AA6283A6C</td>
  <td class=xl65>1</td>
  <td class=xl65>5</td>
  <td class=xl65>10,000+</td>
 </tr>
 <tr class=xl66 height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>ABDFB4B0578EF5B4356EE467593C20276C1901138C06B3B0DCAD514894178F8D</td>
  <td class=xl65>1</td>
  <td class=xl65>4</td>
  <td class=xl65>5,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>B606939B25FE22A2B7CC16024BBADF86462E3E5B18C48F9C5AF8855F8547BE19</td>
  <td class=xl65>1</td>
  <td class=xl65>2</td>
  <td class=xl65>50,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>B8B8513B17F6A989181D0CF0A7D2C88BC97AAA2DC6D7B1D6F007BBF1F75A9840</td>
  <td class=xl65>1</td>
  <td class=xl65>6</td>
  <td class=xl65>5,000,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>B8CDC4518B074E83F888BCF2EA306A576E2EBA6E50EA1AA969970FC8971D865E</td>
  <td class=xl65>1</td>
  <td class=xl65>6</td>
  <td class=xl65>1,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>C307DCD2A47D3E7D32F06C3C2EEB21B99AEBEAC2F3BE15E38CFD44343A598F53</td>
  <td class=xl65>1</td>
  <td class=xl65>2</td>
  <td class=xl65>5000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>C7A6C11F57924F62DDD83CB51721095A5BBF4B020BEEC9908AE7F4C03E2165EB</td>
  <td class=xl65>1</td>
  <td class=xl65>8</td>
  <td class=xl65></td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>CB8EE8EC1B04E9B5B53849C7A2DF9307B7E24CBE0ED531B89990596A4EB339A1</td>
  <td class=xl65>1</td>
  <td class=xl65>1</td>
  <td class=xl65></td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>D6B282CBA77FC5F6E74D7E18A530B6230470FFDE1E8A541720A7DA04C423EFF7</td>
  <td class=xl65>1</td>
  <td class=xl65>4</td>
  <td class=xl65>50,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>DCBB7D663CF5925702CA2D7113DB88138DB00B45F94565A0BE79AB740EB69333</td>
  <td class=xl65>1</td>
  <td class=xl65>6</td>
  <td class=xl65>10,000,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>DCE4161BEB95545A1B4F58B8E2844D541CB1C6F95E2140294F634408208455FF</td>
  <td class=xl65>1</td>
  <td class=xl65>5</td>
  <td class=xl65>5,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>F7B26DE3618F9A07DA363047B8BDA11EC6A8EAD6E35300B14079EA4E3BA6BC5A</td>
  <td class=xl65>1</td>
  <td class=xl65>6</td>
  <td class=xl65>1,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>F8C427FBF4CEA9769B07255D1824299AD1643AD8E6C26131118B4BF9F39C5D86</td>
  <td class=xl65>1</td>
  <td class=xl65>8</td>
  <td class=xl65></td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>FADC9436E6271B71D81CAB1599CDFD79B580B98093F195414140DD2A4FFACAA5</td>
  <td class=xl65>1</td>
  <td class=xl65>1</td>
  <td class=xl65>1,000,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>FC2D7041F133F44B29C6275C025C6F0A1302DE21338C794EC5262EECAA352FF6</td>
  <td class=xl65>1</td>
  <td class=xl65>4</td>
  <td class=xl65>5,000+</td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'></td>
  <td class=xl65></td>
  <td class=xl65></td>
  <td class=xl65></td>
 </tr>
 <tr height=18 style='height:13.5pt'>
  <td height=18 class=xl65 style='height:13.5pt'>48AC996448F06F8BC52EFD0A7AE9D976A178CAF92ED1D4F06017825CE2E9956A</td>
  <td class=xl65>1</td>
  <td class=xl65>0</td>
  <td class=xl65>5,000,000+</td>
 </tr>
 <![if supportMisalignedColumns]>
 <tr height=0 style='display:none'>
  <td width=556 style='width:417pt'></td>
  <td width=76 style='width:57pt'></td>
  <td width=127 style='width:95pt'></td>
  <td width=122 style='width:92pt'></td>
 </tr>
 <![endif]>
</table>

The date we collected the installation information was one week after the detection of these zero-day malware, some of which were deleted by GooglePlay and could not find any information. For the detected malware that can evade detection, the detailed behaviors can be found in the following websit: http://sanddroid.xjtu.edu.cn/report?apk_md5=B8312A75698F1F1EE9768FEB82AC9F93

