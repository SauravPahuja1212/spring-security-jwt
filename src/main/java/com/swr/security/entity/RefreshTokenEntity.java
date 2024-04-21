package com.swr.security.entity;

import com.swr.security.constant.DatabaseConstant;
import com.swr.security.model.RefreshToken;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity(name = DatabaseConstant.RefreshEntity.TABLE_NAME)
public class RefreshTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = DatabaseConstant.RefreshEntity.COLUMN_ID)
    private UUID id;

    @Column(name = DatabaseConstant.RefreshEntity.COLUMN_REFRESH_TOKEN)
    private String refreshToken;

    @Column(name = DatabaseConstant.RefreshEntity.COLUMN_REVOKED)
    private boolean revoked;

    @JoinColumn(name = DatabaseConstant.RefreshEntity.COLUMN_USER_ID, referencedColumnName = DatabaseConstant.User.COLUMN_USER_ID
            , foreignKey = @ForeignKey(name = "refresh_token_user_info_FK"))
    @ManyToOne(fetch = FetchType.EAGER)
    private UserEntity user;

    public RefreshToken convertToModel() {
        RefreshToken token = new RefreshToken();

        token.setId(this.getId());
        token.setRefreshToken(this.getRefreshToken());
        token.setRevoked(this.isRevoked());

        return token;
    }
}
