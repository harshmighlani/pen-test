"""Check registry."""

from apiguard.checks.auth import AuthCheck
from apiguard.checks.business_logic import BusinessLogicCheck
from apiguard.checks.cors_headers import CorsHeadersCheck
from apiguard.checks.data_exposure import DataExposureCheck
from apiguard.checks.injection import InjectionCheck
from apiguard.checks.rate_limit import RateLimitCheck

ALL_CHECKS = {
    AuthCheck.id: AuthCheck,
    InjectionCheck.id: InjectionCheck,
    RateLimitCheck.id: RateLimitCheck,
    DataExposureCheck.id: DataExposureCheck,
    CorsHeadersCheck.id: CorsHeadersCheck,
    BusinessLogicCheck.id: BusinessLogicCheck,
}
