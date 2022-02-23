Imports System
Imports System.Web.HttpUtility

Module Program
    Private T As TM_Client
    Private tf_components As List(Of tmComponent)
    Sub Main(args As String())

        Dim actionWord$ = ""

        actionWord$ = args(0)

        If args.Count.ToString < 1 Or argExist("help", args) Then
            Call giveHelp()
            End
        End If

        Dim fqD$ = argValue("fqdn", args)
        Dim usR$ = argValue("un", args)
        Dim pwD$ = argValue("pw", args)

        If fqD = "" Or usR = "" Or pwD = "" Then
            Console.WriteLine("Must provide --FQDN, --UN and --PW parameters for login.")
            End
        End If

        T = New TM_Client(fqD, usR, pwD)

        If T.isConnected = True Then
            Console.WriteLine("Bearer Token Obtained/ Client connection established.")
        Else
            Console.WriteLine("Unable to obtain Bearer token using provided credentials.")
            End
        End If

        Console.WriteLine(vbCrLf + "ACTION: " + actionWord + vbCrLf)

        Select Case LCase(actionWord)
            Case "submitkiss", "submitkis"
                Dim modelName$ = argValue("modelname", args)
                If Len(modelName) = 0 Then
                    Console.WriteLine("You must provide a new or existing name for the Threat Model using --MODELNAME (name)")
                    End
                End If

                Dim beLoud As Boolean = False
                If LCase(argValue("loud", args)) = "true" Then beLoud = True

                Dim modelNum As Integer
                Dim result2$ = T.createKISSmodelForImport(modelName)
                modelNum = Val(result2)
                If modelNum = 0 Then
                    Console.WriteLine("Unable to create project - " + result2)
                    End
                End If

                Console.WriteLine("Submitting JSON for import into Project #" + modelNum.ToString)

                Dim fileN$ = argValue("file", args)
                If Dir(fileN) = "" Then
                    Console.WriteLine("file does not exist " + fileN)
                End If

                Dim resP$ = T.importKISSmodel(fileN, modelNum)
                If Mid(resP, 1, 5) = "ERROR" Then
                    Console.WriteLine(resP)
                Else
                    Console.WriteLine(T.tmFQDN + "/diagram/" + modelNum.ToString)
                    If beLoud Then Console.WriteLine(resP)
                End If
                End


            Case "submitcfn"
                Dim modelName$ = argValue("modelname", args)

                If Len(modelName) = 0 Then
                    Console.WriteLine("You must provide a new or existing name for the Threat Model using --MODELNAME (name)")
                    End
                End If

                Dim beLoud As Boolean = False
                If LCase(argValue("loud", args)) = "true" Then beLoud = True

                Dim modelNum As Integer
                Dim result2$ = T.createKISSmodelForImport(modelName)
                modelNum = Val(result2)
                If modelNum = 0 Then
                    Console.WriteLine("Unable to create project - " + result2)
                    End
                End If

                Console.WriteLine("Submitting JSON for import into Project #" + modelNum.ToString)

                Dim fileN$ = argValue("file", args)
                If Dir(fileN) = "" Then
                    Console.WriteLine("file does not exist " + fileN)
                End If

                Dim resP$ = T.importKISSmodel(fileN, modelNum, "CloudFormation")
                If Mid(resP, 1, 5) = "ERROR" Then
                    Console.WriteLine(resP)
                Else
                    Console.WriteLine(T.tmFQDN + "/diagram/" + modelNum.ToString)
                    If beLoud Then Console.WriteLine(resP)
                End If
                End


            Case "appscan"
                Dim sDir$ = argValue("dir", args)
                Dim block$ = argValue("block", args)

                Dim publicOnly As Boolean = False
                Dim classesOnly As Boolean = False

                Dim modelType = argValue("type", args)

                Dim showOnlyFiles$ = argValue("onlyfiles", args)
                Dim showClients As Boolean = True
                If LCase(argValue("showclients", args)) = "false" Then showClients = False

                Dim objectsToWatch$ = argValue("objectwatch", args)
                Dim maxdepth As Integer = Val(argValue("depth", args))

                Call loadNTY(T, "Components")
                Dim bestMethod As Integer = T.ndxCompbyName("Method")
                Dim bestRMethod As Integer = T.ndxCompbyName("Return Method")
                Dim bestCC As Integer = T.ndxCompbyName("Code Collection")
                Dim bestCL As Integer = T.ndxCompbyName("Class")
                Dim bestSF As Integer = T.ndxCompbyName("Source File")

                Dim nScan As New appScan

                '                Console.WriteLine("Found AppScan Components:")
                If bestMethod <> -1 Then
                    '                   Console.WriteLine("Method: " + T.lib_Comps(bestMethod).Guid.ToString)
                    nScan.bestMethod = T.lib_Comps(bestMethod).Guid.ToString
                Else
                    Console.WriteLine("Cannot find component 'Method'")
                    End
                End If
                If bestRMethod <> -1 Then
                    '                  Console.WriteLine("Return Method: " + T.lib_Comps(bestRMethod).Guid.ToString)
                    nScan.bestRMethod = T.lib_Comps(bestRMethod).Guid.ToString
                Else
                    Console.WriteLine("Cannot find component 'Return Method'")
                    End
                End If
                If bestCC <> -1 Then
                    '                 Console.WriteLine("Code Collection " + T.lib_Comps(bestCC).Guid.ToString)
                    nScan.bestCC = T.lib_Comps(bestCC).Guid.ToString
                Else
                    Console.WriteLine("Cannot find component 'Code Collection'")
                    End
                End If
                If bestCL <> -1 Then
                    '                Console.WriteLine("Class " + T.lib_Comps(bestCL).Guid.ToString)
                    nScan.bestCL = T.lib_Comps(bestCL).Guid.ToString
                Else
                    Console.WriteLine("Cannot find component 'Class'")
                    End
                End If

                'some change here


                ' some other change


                If bestSF <> -1 Then
                    '               Console.WriteLine("Source File " + T.lib_Comps(bestSF).Guid.ToString)
                    nScan.bestSF = T.lib_Comps(bestSF).Guid.ToString
                Else
                    Console.WriteLine("Cannot find component 'Source File'")
                    End
                End If

                Console.WriteLine("Scanning for classes And methods")
                Dim resulT1$ = ""
                resulT1 = nScan.doScan(sDir, block, objectsToWatch, LCase(modelType), showOnlyFiles, maxdepth, showClients)

                If resulT1 = "ERROR" Or Dir(resulT1) = "" Then
                    Console.WriteLine("Unable to create JSON file")
                    If Dir(resulT1) = "" Then Console.WriteLine("File Not found: " + resulT1)
                    End
                End If



                Dim modelName$ = argValue("modelname", args)
                If modelName = "" Then
                    Console.WriteLine("You must provide a name for the Model using --MODELNAME (name)")
                    End
                End If
                '                modelName = Now.Ticks.ToString + modelName

                Dim modelNum As Integer
                Dim result2$ = T.createKISSmodelForImport(modelName)
                modelNum = Val(result2)
                If modelNum = 0 Then
                    Console.WriteLine("Unable to create project - " + result2)
                    End
                End If

                Console.WriteLine(vbCrLf + "Submitting JSON for import into Project #" + modelNum.ToString)

                Dim resP$ = T.importKISSmodel(resulT1, modelNum)
                If Mid(resP, 1, 5) = "ERROR" Then
                    Console.WriteLine(resP)
                Else
                    Console.WriteLine(T.tmFQDN + "/diagram/" + modelNum.ToString)
                End If
                'Console.WriteLine(T.tmFQDN + "/diagram/" + modelNum.ToString)
                End

        End Select

    End Sub

    Private Sub loadNTY(clienT As TM_Client, ByVal ntyType$)
        Dim R As New tfRequest

        With R
            .LibraryId = 0
            .ShowHidden = False
        End With

        Select Case LCase(ntyType)
            Case "components"
                R.EntityType = "Components"
                clienT.lib_Comps = clienT.getTFComponents(R)
        End Select
    End Sub


    Private Sub giveHelp()
        Console.WriteLine("USAGE: TMCLI action --param1 param1_value --param2 param2_value --fqdn domain.name.com --un username --pw password" + vbCrLf)
        Console.WriteLine("ACTIONS:")
        Console.WriteLine("--------")
        Console.WriteLine(fLine("help", "Produces this list of actions and parameters"))

        Console.WriteLine(fLine("submitkis", "Build Threat Model of JSON in KIS format, arg --MODELNAME (name of threat model) --FILE (json filename)"))
        Console.WriteLine(fLine("submitcfn", "Build Threat Model of CloudFormation Template, arg --MODELNAME (name of threat model) --FILE (cfn filename)"))
        Console.WriteLine(fLine("appscan", "Documentation required, contact ThreatModeler Team for usage"))

    End Sub

End Module
