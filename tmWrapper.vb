Imports RestSharp
Imports Newtonsoft.Json
Imports Newtonsoft.Json.Linq

Public Class TM_Client
    Public lastError$ = ""
    Public tmFQDN$ 'ie http://localhost https://myserver.myzone.com
    Public isConnected As Boolean
    Private slToken$

    Private apiKey$

    Public lib_Comps As List(Of tmComponent)
    Public lib_TH As List(Of tmProjThreat)
    Public lib_SR As List(Of tmProjSecReq)
    Public lib_AT As List(Of tmAttribute)

    Public Sub New(fqdN$, uN$, pw$, Optional ByVal apiK$ = "")
        apiKey = ""

        If Len(apiK) Then
            ' if API KEY provided, do not need un/pw
            apiKey = DecodeBase64(apiK)
            fqdN = Mid(apiKey, InStr(apiKey, "https://") + 8)
            apiKey = apiK
        End If


        If InStr(fqdN, "https://") = 0 Then fqdN = "https://" + fqdN

        tmFQDN = fqdN

        If Len(apiKey) Then
            Me.isConnected = True
            Exit Sub
        End If

        Me.isConnected = False

        Console.WriteLine("Connecting to " + fqdN)
        Dim client = New RestClient(fqdN + "/token")
        Dim request = New RestRequest(Method.POST)
        Dim response As IRestResponse

        client.Timeout = -1

        request.RequestFormat = DataFormat.None

        request.AddHeader("Content-Type", "application/x-www-form-urlencoded")
        request.AddParameter("username", uN)
        request.AddParameter("password", pw)
        request.AddParameter("grant_type", "password")

        response = client.Execute(request)
        Console.WriteLine("Login non-SSO method (demo2): " + response.ResponseStatus.ToString + "/ " + response.StatusCode.ToString + "/ Success: " + response.IsSuccessful.ToString)

        If response.IsSuccessful = False Then
            client = New RestClient(fqdN + "/idsvr/connect/token")
            request = New RestRequest(Method.POST)
            request.AddHeader("Content-Type", "application/x-www-form-urlencoded")
            request.AddHeader("Accept", "application/json")

            request.AddParameter("username", uN)
            request.AddParameter("password", pw)
            request.AddParameter("grant_type", "password")
            request.AddParameter("client_id", "demo-resource-owner")
            request.AddParameter("client_secret", "geheim")
            request.AddParameter("scope", "openid profile email api")

            response = client.Execute(request)
            Console.WriteLine("Login SSO method (/idsvr/connect): " + response.ResponseStatus.ToString + "/ " + response.StatusCode.ToString + "/ Success: " + response.IsSuccessful.ToString)

        End If

        If response.IsSuccessful = True Then
            Me.isConnected = True
            Dim O As JObject = JObject.Parse(response.Content)
            slToken = O.SelectToken("access_token")
            Exit Sub
        End If

        If IsNothing(response.ErrorMessage) = False Then
            lastError = response.ErrorMessage.ToString
        Else
            lastError = response.Content
        End If

        Console.WriteLine(lastError)
        'Console.WriteLine("Retrieved access token")
    End Sub

    Private Function getAPIData(ByVal urI$, Optional ByVal usePOST As Boolean = False, Optional ByVal addJSONbody$ = "", Optional ByVal addingComp As Boolean = False, Optional ByVal returnContent As Boolean = False, Optional ByVal addFileN$ = "") As String
        getAPIData = ""
        If isConnected = False Then Exit Function

        Dim client = New RestClient(tmFQDN + urI)
        Dim request As RestRequest
        If usePOST = False Then request = New RestRequest(Method.GET) Else request = New RestRequest(Method.POST)

        Dim response As IRestResponse

        If apiKey = "" Then request.AddHeader("Authorization", "Bearer " + slToken)
        request.AddHeader("Accept", "application/json")

        If Len(addJSONbody) Then
            If addingComp = False Then
                request.AddHeader("Content-Type", "application/json")
            Else
                request.AddHeader("Content-Type", "multipart/form-data") '; boundary=----WebKitFormBoundary1bCpiyr5KkmiBIAJ")
            End If
            request.AddHeader("Accept-Encoding", "gzip, deflate, br")
            request.AddHeader("Connection", "keep-alive")

            If addingComp = False Then
                request.AddParameter("application/json", addJSONbody, ParameterType.RequestBody)
            Else
                request.AddParameter("data", addJSONbody, ParameterType.RequestBody)
                request.AlwaysMultipartFormData = True
            End If
        End If


        If Len(addFileN) Then
            request.AddFile("File", addFileN)
        End If

        response = client.Execute(request)

        GoTo skipLogging

        ' log details
        Console.WriteLine(request.Method.ToString + " " + tmFQDN + urI)
        For Each hh In response.Headers
            Console.WriteLine(hh.Name.ToString + " " + hh.Value.ToString)
        Next
        For Each pp In request.Parameters
            Console.WriteLine(pp.Name.ToString + " " + pp.Value.ToString)
        Next
        Console.WriteLine("=================CONTENT======================" + vbCrLf + response.Content.ToString)

skipLogging:

        If addingComp Or returnContent Then
            Return response.Content
        End If

        Dim O As JObject = JObject.Parse(response.Content)

        If IsNothing(O.SelectToken("IsSuccess")) = True Then
            Console.WriteLine("API Request Rejected:  " + urI)
            getAPIData = ""
            Exit Function
        End If

        '        If Len(addFileN) Then
        '            If O.SelectToken("IsSuccess").ToString = "true" Then
        '                Return O.SelectToken("IsSuccess").ToString
        '            Else
        '                Return response.Content
        '            End If
        '        End If

        If CBool(O.SelectToken("IsSuccess")) = False Then
            getAPIData = "ERROR:Could not retrieve " + tmFQDN + urI
            Exit Function
        End If

        Return O.SelectToken("Data").ToString
    End Function

    Public Function createKISSmodelForImport(modelName$, Optional ByVal riskId As Integer = 1, Optional ByVal versioN As Integer = 1, Optional ByVal labelS$ = "", Optional ByVal modelType$ = "Others", Optional ByVal importType$ = "Kis") As String
        Dim newM As kisCreateModel_setProject = New kisCreateModel_setProject

        createKISSmodelForImport = ""

        With newM
            .Id = 0
            .Name = modelName
            .RiskId = riskId
            .Version = versioN
            .Labels = labelS
            .Type = modelType
            .CreatedThrough = "Blank"
            .UserPermissions = New List(Of String)
            .GroupPermissions = New List(Of String)
        End With

        Dim jBody$ = JsonConvert.SerializeObject(newM)
        Dim jSon$ = getAPIData("/api/project/create", True, jBody)

        Return jSon
    End Function

    Public Function importKISSmodel(fileN$, projNum As Integer, Optional ByVal integrationType$ = "Kis") As String
        importKISSmodel = ""
        Dim jSon$ = getAPIData("/api/import/" + projNum.ToString + "/" + integrationType, True,,, fileN)

        If Mid(jSon, 1, 5) = "ERROR" Then
            Return jSon
        End If

        Return "Action Completed" + vbCrLf + jSon
    End Function

    Public Function submitCFN_2(fileN$, tmName$) As String
        submitCFN_2 = ""

        Dim templatE As New cfnImport
        With templatE
            .TemplateLanguage = 0
            .TemplateName = tmName
            .Template = streamReaderTxt(fileN)
        End With

        Dim jBody$ = JsonConvert.SerializeObject(templatE)

        'Console.WriteLine("JBODY:" + vbCrLf + jBody)

        Dim jSon$ = getAPIData("/api/plugin/vscode/cloudformation/" + apiKey, True, jBody,, True)

        Dim O As JObject = JObject.Parse(jSon)

        Dim sariF$ = ""

        If IsNothing(O.SelectToken("IsSuccess")) = True Or CBool(O.SelectToken("IsSuccess").ToString) = False Then
            Return "ERROR: API Request Rejected-  " + vbCrLf + jSon
        Else
            sariF = O.SelectToken("Message")
        End If

        Return sariF
    End Function

    Public Function getTFComponents(T As tfRequest) As List(Of tmComponent)
        getTFComponents = New List(Of tmComponent)

        Dim jBody$ = ""
        jBody = JsonConvert.SerializeObject(T)

        Dim jsoN$ = getAPIData("/api/threatframework", True, jBody$)

        getTFComponents = JsonConvert.DeserializeObject(Of List(Of tmComponent))(jsoN)
    End Function

    Public Function ndxCompbyName(name$) As Integer ', ByRef alL As List(Of tmComponent)) As Integer
        ndxCompbyName = -1

        'had to change this as passing byref from multi-threaded main causing issues

        Dim ndX As Integer = 0
        For Each P In lib_Comps
            If LCase(P.Name) = LCase(name) Then
                Return ndX
                Exit Function
            End If
            ndX += 1
        Next

    End Function

End Class

Public Class kisCreateModel_setProject
    Public Id As Integer
    Public Name As String
    Public RiskId As Integer
    Public Labels As String
    Public Version As Integer
    Public isValidFile As Boolean
    Public [Type] As String
    Public CreatedThrough As String
    Public UserPermissions As List(Of String)
    Public GroupPermissions As List(Of String)
End Class

Public Class cfnImport
    Public TemplateName As String
    Public Template As String
    Public TemplateLanguage As Integer
End Class

Public Class tfRequest
    Public EntityType$
    Public LibraryId As Integer '0 = ALL
    Public ShowHidden As Boolean
End Class

Public Class tmComponent
    Public Id As Long
    Public Name$
    Public Description$
    Public ImagePath$
    Public Labels$
    Public Version$
    Public LibraryId As Integer
    Public ComponentTypeId As Integer
    Public ComponentTypeName$
    Public Color$
    Public Guid? As System.Guid
    Public IsHidden As Boolean
    Public DiagralElementId As Integer
    Public ResourceTypeValue$
    'Public Attributes$

    Public listThreats As List(Of tmProjThreat)
    Public listDirectSRs As List(Of tmProjSecReq)
    Public listTransSRs As List(Of tmProjSecReq)
    Public listAttr As List(Of tmAttribute)
    Public isBuilt As Boolean

    Public duplicateSRs As Collection

    Public Function numLabels() As Integer
        If Len(Labels) = 0 Then
            Return 0
        Else
            Return numCHR(Labels, ",") + 1
        End If
    End Function

    Public ReadOnly Property CompID() As Long
        Get
            Return Id
        End Get
    End Property
    Public ReadOnly Property CompName() As String
        Get
            Return Name
        End Get
    End Property
    Public ReadOnly Property TypeName() As String
        Get
            Return ComponentTypeName
        End Get
    End Property
    Public ReadOnly Property NumTH() As Integer
        Get
            Return listThreats.Count
        End Get
    End Property

    Public ReadOnly Property NumSR() As Integer
        Get
            Return listDirectSRs.Count + listTransSRs.Count
        End Get
    End Property

    Public Sub New()
        listThreats = New List(Of tmProjThreat)
        listDirectSRs = New List(Of tmProjSecReq)
        listTransSRs = New List(Of tmProjSecReq)
        listAttr = New List(Of tmAttribute)
        isBuilt = False
        duplicateSRs = New Collection
    End Sub

End Class

Public Class tmProjSecReq
    Public Id As Long
    Public Name$
    Public Description$
    Public RiskId As Integer
    Public IsCompensatingControl As Boolean
    Public RiskName$
    Public Labels$
    Public LibraryId As Integer
    Public Guid? As System.Guid
    Public StatusName$
    Public SourceName$
    Public IsHidden As Boolean
End Class

Public Class tmProjThreat
    Public Id As Long
    Public Guid? As System.Guid 'nulls
    Public Name$
    Public Description$
    Public RiskId As Integer
    Public RiskName$
    Public LibraryId As Integer
    Public Labels$
    Public Reference$
    Public Automated As Boolean
    Public StatusName$
    Public IsHidden As Boolean
    Public CompanyId As Integer
    Public isDefault As Boolean
    Public DateCreated$
    Public LastUpdated$
    Public DepartmentId As Integer
    Public DepartmentName$
    Public IsSystemDepartment As Boolean
    Public isBuilt As Boolean
    Public listLinkedSRs As Collection

    Public ReadOnly Property ThrID
        Get
            Return Id
        End Get
    End Property
    Public ReadOnly Property ThrName
        Get
            Return Name
        End Get
    End Property
    Public ReadOnly Property ThRisk
        Get
            Return RiskName
        End Get
    End Property
    Public Sub New()
        listLinkedSRs = New Collection
    End Sub
End Class

Public Class tmAttribute
    Public Id As Long
    Public Guid? As Guid
    Public Name$
    Public LibraryId As Integer
    Public Options() As tmOptions ' As List(Of tmOptions)

    Public Sub New()
        '        Options = New List(Of tmOptions)
    End Sub

End Class
Public Class tmOptions
    Public Id As Integer
    Public Name$
    Public isDefault As Boolean
    Public Threats() As tmProjThreat

    Public Sub New()
        '        Threats = New List(Of tmProjThreat)
    End Sub
End Class


