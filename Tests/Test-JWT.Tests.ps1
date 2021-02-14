Describe "Test-JWT" {
    BeforeAll {
        Import-Module -Name jwtPS
    }
    Context "Verify mandatory Parameter" {
        $mandatoryParameter = @(
            @{ 
                parameter = 'JWT'
                parameterset = 'RSA'
            }
            @{ 
                parameter = 'JWT'
                parameterset = 'HMAC'
            }
            @{ 
                parameter = 'PublicKey'
                parameterset = 'RSA'
            }
            @{ 
                parameter = 'Secret'
                parameterset = 'HMAC'
            }
        )
        It "<parameter> is mandatory in parameter set <parameterset>" -TestCases $mandatoryParameter {
            param($parameter, $parameterset)
            $command = Get-Command -Name Test-JWT
            $command.Parameters[$parameter].ParameterSets[$parameterset].IsMandatory | Should -BeTrue
        }
    }
}